import { authenticate } from "../drivers/auth";
import { doc, guard } from "../drivers/firestore";
import { AWS_API_VERSION } from "../plugins/aws/api";
import { AwsCredentials } from "../plugins/aws/types";
import { assumeRoleWithOktaSaml } from "../plugins/okta/aws";
import { Authn } from "../types/identity";
import {
  DENIED_STATUSES,
  DONE_STATUSES,
  ERROR_STATUSES,
  Request,
} from "../types/request";
import { sleep } from "../util";
import { request } from "./request";
import {
  SSMClient,
  StartSessionCommand,
  StartSessionCommandInput,
} from "@aws-sdk/client-ssm";
import { onSnapshot } from "firebase/firestore";
import { pick } from "lodash";
import { ChildProcessByStdio, spawn } from "node:child_process";
import { Readable } from "node:stream";
import yargs from "yargs";

/** Matches the error message that AWS SSM prints when access is not propagated */
// Note that the resource will randomly be either the SSM document or the EC2 instance
const UNPROVISIONED_ACCESS_MESSAGE =
  /An error occurred \(AccessDeniedException\) when calling the StartSession operation\: User\: arn\:aws\:sts\:\:.*\:assumed-role\/P0GrantsRole.* is not authorized to perform\: ssm\:StartSession on resource\: arn\:aws\:.*\:.*\:.* because no identity-based policy allows the ssm\:StartSession action/;
/** Maximum amount of time after AWS SSM process starts to check for {@link UNPROVISIONED_ACCESS_MESSAGE}
 *  in the process's stderr
 */
const UNPROVISIONED_ACCESS_VALIDATION_WINDOW_MS = 5e3;
/** Maximum number of attempts to start an SSM session */
const MAX_SSM_RETRIES = 30;

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

// TODO: Move this to a shared utility
/** Waits until P0 grants access for a request */
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

/** Polls AWS until `ssm:StartSession` succeeds, or {@link ACCESS_TIMEOUT_MILLIS} passes */
const waitForSsmAccess = async (args: SsmArgs) => {
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

/** Checks if access has propagated through AWS to the SSM agent
 *
 * AWS takes about 8 minutes to fully resolve access after it is granted. During
 * this time, calls to `aws ssm start-session` will fail randomly with an
 * access denied exception.
 *
 * This function checks AWS to see if this exception is printed to the SSM
 * error output within the first 5 seconds of startup. If it is, the returned
 * `isAccessPropagated()` function will return false. When this occurs, the
 * consumer of this function should retry the AWS SSM session.
 *
 * Note that this function requires interception of the AWS SSM stderr stream.
 * This works because AWS SSM wraps the session in a single-stream pty, so we
 * do not capture stderr emmitted from the wrapped shell session.
 */
const accessPropagationGuard = (
  child: ChildProcessByStdio<any, any, Readable>
) => {
  let isEphemeralAccessDeniedException = false;
  const beforeStart = Date.now();

  child.stderr.on("data", (chunk) => {
    const chunkString = chunk.toString("utf-8");
    const match = chunkString.match(UNPROVISIONED_ACCESS_MESSAGE);

    if (
      match &&
      Date.now() <= beforeStart + UNPROVISIONED_ACCESS_VALIDATION_WINDOW_MS
    ) {
      isEphemeralAccessDeniedException = true;
      return;
    }

    console.error(chunkString);
  });

  return {
    isAccessPropagated: () => !isEphemeralAccessDeniedException,
  };
};

/** Starts an SSM session in the terminal by spawning `aws ssm` as a subprocess
 *
 * Requires `aws ssm` to be installed on the client machine.
 */
const spawnSsmNode = async (
  args: Pick<SsmArgs, "region" | "credential">,
  commandInput: StartSessionCommandInput,
  options?: { attemptsRemaining?: number }
): Promise<number | null> =>
  new Promise((resolve, reject) => {
    if (!commandInput.Target || !commandInput.DocumentName) {
      reject("Command input is missing required fields: Target, DocumentName");
      return;
    }

    const ssmCommand = [
      "aws",
      "ssm",
      "start-session",
      "--region",
      args.region,
      "--target",
      commandInput.Target,
      "--document-name",
      commandInput.DocumentName,
    ];
    const child = spawn("/usr/bin/env", ssmCommand, {
      env: {
        ...process.env,
        ...args.credential,
      },
      stdio: ["inherit", "inherit", "pipe"],
    });

    const { isAccessPropagated } = accessPropagationGuard(child);

    const exitListener = child.on("exit", (code) => {
      exitListener.unref();

      // In the case of ephemeral AccessDenied exceptions due to unpropagated
      // permissions, continually retry access until success
      if (!isAccessPropagated()) {
        const attemptsRemaining = options?.attemptsRemaining ?? MAX_SSM_RETRIES;
        if (attemptsRemaining <= 0) {
          reject(
            "Access did not propagate through AWS before max retry attempts were exceeded. Please contact support@p0.dev for assistance."
          );
          return;
        }
        // console.debug("Permissions not yet propagated in AWS; retrying");
        spawnSsmNode(args, commandInput, {
          ...(options ?? {}),
          attemptsRemaining: attemptsRemaining - 1,
        })
          .then((code) => resolve(code))
          .catch(reject);
        return;
      }

      console.error("SSH session terminated");
      resolve(code);
    });
  });

/** Connect to an SSH backend using AWS Systems Manager (SSM) */
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
  const commandInput = await waitForSsmAccess(args);
  await spawnSsmNode(args, commandInput);
};

/** Connect to an SSH backend
 *
 * Implicitly gains access to the SSH resource if required.
 */
const ssh = async (args: yargs.ArgumentsCamelCase<{ instance: string }>) => {
  // Prefix is required because the backend uses it to determine that this is an AWS request
  const authn = await authenticate();
  const response = await request(
    {
      ...pick(args, "$0", "_"),
      arguments: ["ssh", args.instance, "--provider", "aws"],
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
