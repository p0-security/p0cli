/** Copyright © 2024-present P0 Security

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { SshCommandArgs } from "../../../commands/ssh";
import { print2 } from "../../../drivers/stdio";
import { Authn } from "../../../types/identity";
import { Request } from "../../../types/request";
import { assumeRoleWithOktaSaml } from "../../okta/aws";
import { AwsCredentials, AwsSsh } from "../types";
import { ensureSsmInstall } from "./install";
import { ChildProcessByStdio, spawn } from "node:child_process";
import { Readable } from "node:stream";

/** Matches the error message that AWS SSM print1 when access is not propagated */
// Note that the resource will randomly be either the SSM document or the EC2 instance
const UNPROVISIONED_ACCESS_MESSAGE =
  /An error occurred \(AccessDeniedException\) when calling the StartSession operation: User: arn:aws:sts::.*:assumed-role\/P0GrantsRole.* is not authorized to perform: ssm:StartSession on resource: arn:aws:.*:.*:.* because no identity-based policy allows the ssm:StartSession action/;

/** Maximum amount of time after AWS SSM process starts to check for {@link UNPROVISIONED_ACCESS_MESSAGE}
 *  in the process's stderr
 */
const UNPROVISIONED_ACCESS_VALIDATION_WINDOW_MS = 5e3;

/** Maximum number of attempts to start an SSM session
 *
 * Note that each attempt consumes ~ 1 s.
 */
const MAX_SSM_RETRIES = 30;

const INSTANCE_ARN_PATTERN =
  /^arn:aws:ssm:([^:]+):([^:]+):managed-instance\/([^:]+)$/;

/** The name of the SessionManager port forwarding document. This document is managed by AWS.  */
const LOCAL_PORT_FORWARDING_DOCUMENT_NAME = "AWS-StartPortForwardingSession";

type SsmArgs = {
  instance: string;
  region: string;
  requestId: string;
  documentName: string;
  credential: AwsCredentials;
  command?: string;
  forwardPortAddress?: string;
};

/** Checks if access has propagated through AWS to the SSM agent
 *
 * AWS takes about 8 minutes to fully resolve access after it is granted. During
 * this time, calls to `aws ssm start-session` will fail randomly with an
 * access denied exception.
 *
 * This function checks AWS to see if this exception is print1d to the SSM
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

    print2(chunkString);
  });

  return {
    isAccessPropagated: () => !isEphemeralAccessDeniedException,
  };
};

const createSsmCommand = (args: Omit<SsmArgs, "requestId">) => {
  const hasCommand = args.command && args.command.trim();

  if (hasCommand && args.forwardPortAddress) {
    throw "Invalid arguments. Specify either a command or port forwarding, not both.";
  }

  const ssmCommand = [
    "aws",
    "ssm",
    "start-session",
    "--region",
    args.region,
    "--target",
    args.instance,
    "--document-name",
    // Port forwarding is a special case that uses an AWS-managed document and
    // not the user-generated document we use for an SSH session
    args.forwardPortAddress
      ? LOCAL_PORT_FORWARDING_DOCUMENT_NAME
      : args.documentName,
  ];

  if (hasCommand) {
    ssmCommand.push("--parameters", `command='${args.command}'`);
  } else if (args.forwardPortAddress) {
    const [localPort, remotePort] = args.forwardPortAddress.split(":");

    ssmCommand.push(
      "--parameters",
      `localPortNumber=${localPort},portNumber=${remotePort}`
    );
  }

  return ssmCommand;
};

/** Starts an SSM session in the terminal by spawning `aws ssm` as a subprocess
 *
 * Requires `aws ssm` to be installed on the client machine.
 */
const spawnSsmNode = async (
  args: Omit<SsmArgs, "requestId">,
  options?: { attemptsRemaining?: number }
): Promise<number | null> =>
  new Promise((resolve, reject) => {
    const ssmCommand = createSsmCommand(args);
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
        spawnSsmNode(args, {
          ...(options ?? {}),
          attemptsRemaining: attemptsRemaining - 1,
        })
          .then((code) => resolve(code))
          .catch(reject);
        return;
      }

      print2("SSH session terminated");
      resolve(code);
    });
  });

/** Convert an SshCommandArgs into an SSM document "command" parameter */
const commandParameter = (args: SshCommandArgs) =>
  args.command
    ? `${args.command} ${args.arguments
        .map(
          (argument) =>
            // escape all double quotes (") in commands such as `p0 ssh <instance>> echo 'hello; "world"'` because we
            // need to encapsulate command arguments in double quotes as we pass them along to the remote shell
            `"${argument.replace(/"/g, '\\"')}"`
        )
        .join(" ")}`.trim()
    : undefined;

/** Connect to an SSH backend using AWS Systems Manager (SSM) */
export const ssm = async (
  authn: Authn,
  request: Request<AwsSsh> & {
    id: string;
  },
  args: SshCommandArgs
) => {
  const isInstalled = await ensureSsmInstall();
  if (!isInstalled)
    throw "Please try again after installing the required AWS utilities";

  const match = request.permission.spec.arn.match(INSTANCE_ARN_PATTERN);
  if (!match) throw "Did not receive a properly formatted instance identifier";
  const [, region, account, instance] = match;

  const credential = await assumeRoleWithOktaSaml(authn, {
    account,
    role: request.generatedRoles[0]!.role,
  });
  const ssmArgs = {
    instance: instance!,
    region: region!,
    documentName: request.generated.documentName,
    requestId: request.id,
    forwardPortAddress: args.L,
    credential,
    command: commandParameter(args),
  };
  await spawnSsmNode(ssmArgs);
};
