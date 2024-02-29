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
import { Readable, Transform } from "node:stream";

export const INVALID_PORT_FORWARD_FORMAT_ERROR_MESSAGE =
  "Local port forward should be in the format `local_port:remote_port`";

const STARTING_SESSION_MESSAGE = /Starting session with SessionId: (.*)/;

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
  command?: string;
  forwardPortAddress?: string;
};

const parseBuffer = (fn: (message: string) => void) => (buffer: Buffer) => {
  const message = buffer.toString("utf-8");
  fn(message);
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

  child.stderr.on(
    "data",
    parseBuffer((message) => {
      const match = message.match(UNPROVISIONED_ACCESS_MESSAGE);

      if (
        match &&
        Date.now() <= beforeStart + UNPROVISIONED_ACCESS_VALIDATION_WINDOW_MS
      ) {
        isEphemeralAccessDeniedException = true;
        return;
      }

      print2(message);
    })
  );

  return {
    isAccessPropagated: () => !isEphemeralAccessDeniedException,
  };
};

const createBaseSsmCommand = (args: Omit<SsmArgs, "requestId">) => {
  return [
    "aws",
    "ssm",
    "start-session",
    "--region",
    args.region,
    "--target",
    args.instance,
  ];
};

const createInteractiveShellCommand = (args: Omit<SsmArgs, "requestId">) => {
  const ssmCommand = [
    ...createBaseSsmCommand(args),
    "--document-name",
    args.documentName,
  ];

  const command = args.command?.trim();
  if (command) {
    ssmCommand.push("--parameters", `command='${command}'`);
  }

  return ssmCommand;
};

const createPortForwardingCommand = (args: Omit<SsmArgs, "requestId">) => {
  if (!args.forwardPortAddress) throw INVALID_PORT_FORWARD_FORMAT_ERROR_MESSAGE;

  const [localPort, remotePort] = args.forwardPortAddress.split(":");

  return [
    ...createBaseSsmCommand(args),
    "--document-name",
    // Port forwarding is a special case that uses an AWS-managed document, not the user-generated document we use for an SSH session
    LOCAL_PORT_FORWARDING_DOCUMENT_NAME,
    "--parameters",
    `localPortNumber=${localPort},portNumber=${remotePort}`,
  ];
};

const createSsmCommands = (
  args: Omit<SsmArgs, "requestId">
): { command: string[]; subcommand?: string[] } => {
  const command = createInteractiveShellCommand(args);

  if (args.forwardPortAddress) {
    return {
      command,
      subcommand: createPortForwardingCommand(args),
    };
  }

  return {
    command,
  };
};

/**
 * Manages the lifecycle of child processes that execute AWS SSM commands
 * @param credentials AWS credentials to be passed to the child processes for executing AWS SSM commands
 */
const subcommandManager = (credentials: AwsCredentials) => {
  const children: ChildProcessByStdio<any, any, any>[] = [];
  const streamClosers: (() => void)[] = [];

  return {
    /**
     * Executes an AWS SSM command in a child process and creates a stream to suppress the {@link STARTING_SESSION_MESSAGE} from the child process
     * @param command The command to be executed in the child process
     */
    executeCommand: (command: string[]) => {
      const subprocess = spawn("/usr/bin/env", command, {
        env: {
          ...process.env,
          ...credentials,
        },
        stdio: ["inherit", "pipe", "pipe"],
        detached: true,
      });

      const stream = sessionOutputStream(subprocess, {
        suppressStartSessionMessage: true,
      });

      streamClosers.push(stream.close);
      children.push(subprocess);
    },
    /**
     * Terminates all child processes, their respective subprocesses, and any associated streams
     */
    killProcesses: () => {
      streamClosers.forEach((closer) => closer());
      children.forEach((child) => {
        if (child.pid) {
          process.kill(-child.pid);
        } else {
          // Emergency attempt to kill the child process,
          // in theory the PID should be always be available.
          child.kill("SIGKILL");
        }
      });
    },
  };
};

/**
 * Creates a stream that intercepts the output of the child process running the SSM session command and triggers a callback when the SSM session starts
 * @param child The child process that is running the SSM session command
 * @param options.suppressStartSessionMessage Whether to suppress the {@link STARTING_SESSION_MESSAGE} from being printed to the terminal
 */
const sessionOutputStream = (
  child: ChildProcessByStdio<any, Readable, any>,
  options?: {
    suppressStartSessionMessage: boolean;
  }
) => {
  const callbacks: (() => void)[] = [];

  // Create a transform stream to duplicate the data
  const proxyStream = new Transform({
    transform(chunk, _, end) {
      parseBuffer((message) => {
        // spawn subprocesses when the SSM session starts
        const match = message.match(STARTING_SESSION_MESSAGE);
        if (match) {
          for (const callback of callbacks) {
            callback();
          }
        }

        if (!options?.suppressStartSessionMessage || !match) {
          // Pass the original chunk through
          this.push(chunk);
        }

        end();
      })(chunk);
    },
  });

  // ensures that content from the child process is printed to the terminal even though we're piping it to a stream
  child.stdout.pipe(proxyStream).pipe(process.stdout);

  return {
    onSessionStart: (callback: () => void) => {
      callbacks.push(callback);
    },
    close: () => {
      proxyStream.destroy();
    },
  };
};

/** Starts an SSM session in the terminal by spawning `aws ssm` as a subprocess
 *
 * Requires `aws ssm` to be installed on the client machine.
 */
const spawnSsmNode = async (
  credentials: AwsCredentials,
  options: {
    command: string[];
    attemptsRemaining?: number;
    subcommand?: string[];
  }
): Promise<number | null> =>
  new Promise((resolve, reject) => {
    const parent = spawn("/usr/bin/env", options.command, {
      env: {
        ...process.env,
        ...credentials,
      },
      stdio: ["inherit", "pipe", "pipe"],
    });
    const stream = sessionOutputStream(parent);
    const subprocesses = subcommandManager(credentials);

    stream.onSessionStart(() => {
      const subcommand = options?.subcommand ?? [];
      if (subcommand.length) {
        subprocesses.executeCommand(subcommand);
      }
    });

    const { isAccessPropagated } = accessPropagationGuard(parent);

    const exitListener = parent.on("exit", (code) => {
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
        spawnSsmNode(credentials, {
          ...options,
          attemptsRemaining: attemptsRemaining - 1,
        })
          .then((code) => resolve(code))
          .catch(reject);
        return;
      }

      subprocesses.killProcesses();
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
            `"${String(argument).replace(/"/g, '\\"')}"`
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
    command: commandParameter(args),
  };
  await spawnSsmNode(credential, {
    ...createSsmCommands(ssmArgs),
  });
};
