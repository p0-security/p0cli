import { authenticate } from "../../drivers/auth";
import { doc, guard } from "../../drivers/firestore";
import { AWS_API_VERSION } from "../../plugins/aws/api";
import { assumeRoleWithSaml } from "../../plugins/aws/assumeRole";
import { AwsCredentials } from "../../plugins/aws/types";
import { Authn } from "../../types/identity";
import {
  DENIED_STATUSES,
  DONE_STATUSES,
  ERROR_STATUSES,
  Request,
} from "../../types/request";
import { sleep } from "../../util";
import { initOktaSaml } from "../aws/role";
import { request } from "../request";
import { SSMClient, StartSessionCommand } from "@aws-sdk/client-ssm";
import { onSnapshot } from "firebase/firestore";
import { pick } from "lodash";
import { spawn } from "node-pty";
import yargs from "yargs";

const prefix = "arn:aws:ssm:us-west-2:391052057035:managed-instance/";

/** Maximum amount of time to wait after access is approved to wait for access
 *  to be configured
 */
const GRANT_TIMEOUT_MILLIS = 60e3;

/** Maximum amount of time to wait after access is configured in AWS to wait
 *  for access to propagate through AWS
 */
const ACCESS_TIMEOUT_MILLIS = 5e3;
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
  while (Date.now() - start < ACCESS_TIMEOUT_MILLIS) {
    try {
      // We don't use this response for anything; we just need this to succeed
      await client.send(
        new StartSessionCommand({
          Target: args.instance,
          Reason: "Test connectivity",
        })
      );
      return;
    } catch (error: any) {
      if (error.__type === "AccessDeniedException") {
        lastError = error;
        await sleep(ACCESS_CHECK_INTERVAL_MILLIS);
      } else throw error;
    }
  }
  throw lastError;
};

const spawnSsm = async (args: SsmArgs) =>
  new Promise((resolve, _reject) => {
    const cols = process.stdout.columns ?? 80;
    const rows = process.stdout.rows ?? 50;
    const child = spawn(
      "/usr/bin/env",
      [
        "aws",
        "ssm",
        "start-session",
        "--target",
        args.instance,
        // "--document-name",
        // ssmDocumentArn(args.requestId),
      ],
      {
        env: {
          ...process.env,
          ...args.credential,
          AWS_DEFAULT_REGION: args.region,
        },
        rows,
        cols,
      }
    );
    process.stdout.on("resize", () => {
      child.resize(process.stdout.columns, process.stdout.rows);
    });
    process.stdin.setRawMode(true);
    process.stdin.setEncoding("utf-8");
    const stdinListener = process.stdin.on("data", (d) =>
      child.write(d.toString("utf-8"))
    );
    process.stdin.resume();
    // TODO: separate stdout / stderr
    const outListener = child.onData((d) => process.stdout.write(d));
    const exitListener = child.onExit((code) => {
      process.stdin.setRawMode(false);
      process.stdin.resume();
      stdinListener.destroy();
      outListener.dispose();
      exitListener.dispose();
      console.error("SSH session terminated");
      resolve(code);
    });
  });

const ssm = async (authn: Authn, request: Request<AwsSsh> & { id: string }) => {
  const match = request.permission.spec.arn.match(INSTANCE_ARN_PATTERN);
  if (!match) throw "Did not receive a properly formatted instance identifier";
  const [, region, account, instance] = match;

  const { config, samlResponse } = await initOktaSaml(authn, account);
  const bastionCredential = await assumeRoleWithSaml({
    account: account!,
    role: request.generatedRoles[0]!.role,
    saml: {
      providerName: config.uidLocation.samlProviderName,
      response: samlResponse,
    },
  });
  const args = {
    instance: instance!,
    region: region!,
    requestId: request.id,
    credential: bastionCredential,
  };
  await waitForAccess(args);
  await spawnSsm(args);
};

const ssh = async (args: yargs.ArgumentsCamelCase<{ instance: string }>) => {
  const arn = `${prefix}${args.instance}`;
  const authn = await authenticate();
  const response = await request(
    {
      ...pick(args, "$0", "_"),
      arguments: ["ssh", "session", arn],
      wait: true,
    },
    authn,
    { message: "approval-required" }
  );
  // Hard code for testing only
  // const requestId = "v0SMHf4BbbGj6NOQrdjx";
  if (!response) {
    console.error("Did not receive access ID from server");
    return;
  }
  const { id, isPreexisting } = response;
  if (!isPreexisting) console.error("Waiting for access to be provisioned");
  const requestData = await waitForProvisioning(authn, id);
  await ssm(authn, { ...requestData, id });
};
