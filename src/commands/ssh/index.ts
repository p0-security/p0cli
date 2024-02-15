import { authenticate } from "../../drivers/auth";
import { doc, guard } from "../../drivers/firestore";
import { AWS_API_VERSION } from "../../plugins/aws/api";
import { AwsCredentials } from "../../plugins/aws/types";
import { assumeRoleWithOktaSaml } from "../../plugins/okta/aws";
import { Authn } from "../../types/identity";
import {
  DENIED_STATUSES,
  DONE_STATUSES,
  ERROR_STATUSES,
  Request,
} from "../../types/request";
import { sleep } from "../../util";
import { request } from "../request";
import {
  SSMClient,
  StartSessionCommand,
  StartSessionCommandInput,
} from "@aws-sdk/client-ssm";
import { onSnapshot } from "firebase/firestore";
import { pick } from "lodash";
import { spawn } from "node:child_process";
import yargs from "yargs";

const awsRequestPrefix = "AWS:";

/** Maximum amount of time to wait after access is approved to wait for access
 *  to be configured
 */
const GRANT_TIMEOUT_MILLIS = 60e3;

/** Maximum amount of time to wait after access is configured in AWS to wait
 *  for access to propagate through AWS
 */
const ACCESS_TIMEOUT_MILLIS = 30e3;
/** Polling interval for the above check */
const ACCESS_CHECK_INTERVAL_MILLIS = 200;

const INSTANCE_ARN_PATTERN =
  /^arn:aws:ssm:([^:]+):([^:]+):managed-instance\/([^:]+)$/;

const ssmDocumentArn = (requestId: string) =>
  `P0SshAsUser-${requestId}-nathan_brahms`;

type AwsSsh = {
  spec: {
    arn: string;
  };
  type: "session";
};

type SsmArgs = {
  instance: string;
  region: string;
  requestId: string;
  documentName: string;
  credential: AwsCredentials;
};

export const sshCommand = (yargs: yargs.Argv) =>
  yargs.command<{ instance: string }>(
    "ssh <instance>",
    "SSH into a virtual machine",
    (yargs) =>
      yargs.positional("instance", {
        type: "string",
        demandOption: true,
      }),
    guard(ssh)
  );

const waitForProvisioning = async (authn: Authn, requestId: string) => {
  let cancel: NodeJS.Timeout | undefined = undefined;
  const result = await new Promise<Request<AwsSsh>>((resolve, reject) => {
    let isResolved = false;
    const unsubscribe = onSnapshot<Request<AwsSsh>, object>(
      doc(`o/${authn.identity.org.tenantId}/permission-requests/${requestId}`),
      (snap) => {
        const data = snap.data();
        if (!data) return;
        if (DONE_STATUSES.includes(data.status as any)) {
          resolve(data);
        } else if (DENIED_STATUSES.includes(data.status as any)) {
          reject("Your access request was denied");
        } else if (ERROR_STATUSES.includes(data.status as any)) {
          reject(
            "Your access request encountered an error (see Slack for details)"
          );
        } else {
          return;
        }
        isResolved = true;
        unsubscribe();
      }
    );
    cancel = setTimeout(() => {
      if (!isResolved) {
        unsubscribe();
        reject("Timeout awaiting SSH access grant");
      }
    }, GRANT_TIMEOUT_MILLIS);
  });
  clearTimeout(cancel);
  return result;
};

const waitForAccess = async (args: SsmArgs) => {
  const start = Date.now();
  let lastError: any = undefined;
  const client = new SSMClient({
    apiVersion: AWS_API_VERSION,
    region: args.region,
    credentials: {
      accessKeyId: args.credential.AWS_ACCESS_KEY_ID,
      secretAccessKey: args.credential.AWS_SECRET_ACCESS_KEY,
      sessionToken: args.credential.AWS_SESSION_TOKEN,
    },
  });
  const commandInput: StartSessionCommandInput = {
    Target: args.instance,
    DocumentName: args.documentName,
  };
  while (Date.now() - start < ACCESS_TIMEOUT_MILLIS) {
    try {
      // We don't use this response for anything; we just need this to succeed
      await client.send(
        new StartSessionCommand({
          ...commandInput,
          Reason: "Test connectivity",
        })
      );
      return commandInput;
    } catch (error: any) {
      if (error.__type === "AccessDeniedException") {
        lastError = error;
        await sleep(ACCESS_CHECK_INTERVAL_MILLIS);
      } else throw error;
    }
  }
  throw lastError;
};

const spawnSsmNode = async (
  args: Pick<SsmArgs, "region" | "credential">,
  commandInput: StartSessionCommandInput
) =>
  new Promise((resolve, reject) => {
    if (!commandInput.Target || !commandInput.DocumentName) {
      reject("Command input is missing required fields: Target, DocumentName");
      return;
    }
    const child = spawn(
      "/usr/bin/env",
      [
        "aws",
        "ssm",
        "start-session",
        "--target",
        commandInput.Target,
        "--document-name",
        commandInput.DocumentName,
      ],
      {
        env: {
          ...process.env,
          ...args.credential,
          AWS_DEFAULT_REGION: args.region,
        },
        stdio: "inherit",
      }
    );

    const exitListener = child.on("exit", (code) => {
      exitListener.unref();
      console.error("SSH session terminated");
      resolve(code);
    });
  });

const ssm = async (authn: Authn, request: Request<AwsSsh> & { id: string }) => {
  const match = request.permission.spec.arn.match(INSTANCE_ARN_PATTERN);
  if (!match) throw "Did not receive a properly formatted instance identifier";
  const [, region, account, instance] = match;

  const credential = await assumeRoleWithOktaSaml(authn, {
    account,
    role: request.generatedRoles[0]!.role,
  });
  const args = {
    instance: instance!,
    region: region!,
    documentName: request.generated.documentName,
    requestId: request.id,
    credential,
  };
  const commandInput = await waitForAccess(args);
  await spawnSsmNode(args, commandInput);
};

const ssh = async (args: yargs.ArgumentsCamelCase<{ instance: string }>) => {
  // Prefix is required because the backend uses it to determine that this is an AWS request
  const authn = await authenticate();
  const response = await request(
    {
      ...pick(args, "$0", "_"),
      arguments: ["ssh", "session", args.instance, "--provider", "aws"],
      wait: true,
    },
    authn,
    { message: "approval-required" }
  );
  if (!response) {
    console.error("Did not receive access ID from server");
    return;
  }
  const { id, isPreexisting } = response;
  if (!isPreexisting) console.error("Waiting for access to be provisioned");
  const requestData = await waitForProvisioning(authn, id);
  await ssm(authn, { ...requestData, id });
};
