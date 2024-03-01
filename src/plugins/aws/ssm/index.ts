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

const createPortForwardingCommand = (
  args: Omit<SsmArgs, "requestId"> &
    Required<Pick<SsmArgs, "forwardPortAddress">>
) => {
  const [localPort, remotePort] = args.forwardPortAddress
    .split(":")
    .map(Number);

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

  const forwardPortAddress = args.forwardPortAddress;
  if (forwardPortAddress) {
    return {
      command,
      subcommand: createPortForwardingCommand({ ...args, forwardPortAddress }),
    };
  }

  return {
    command,
  };
};

/**
 * Manages the lifecycle of child processes that run AWS SSM commands.
 *
 * This includes spawning child processes, creating streams to process output, and terminating the child processes, their respective subprocesses, and their related streams.
 *
 * @param credentials AWS credentials to be passed to the child processes for executing AWS SSM commands
 */
const subcommandLauncher = (credentials: AwsCredentials) => {
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
        // Using a detached process group ensures that the child's subprocesses can be killed when the parent process is terminated
        detached: true,
      });

      const stream = interceptSessionOutput(subprocess, {
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
        if (child.pid && !child.killed) {
          // Tells the parent process to kill the child process and all of it's descendants.
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
 * Uses a stream to intercept the output of a {@link childProcess} running a command and triggers a callback when the SSM session starts.
 *
 * The start of an SSM session is detected by the {@link STARTING_SESSION_MESSAGE} being printed to the stdout.
 *
 * @param childProcess The child process that is running the SSM session command
 * @param onSessionStart The callback to be triggered when the SSM session starts
 * @param suppressStartSessionMessage Whether to suppress the {@link STARTING_SESSION_MESSAGE} from being printed to the terminal
 */
const interceptSessionOutput = (
  childProcess: ChildProcessByStdio<any, Readable, any>,
  options: {
    onSessionStart?: () => void;
    suppressStartSessionMessage?: boolean;
  }
) => {
  // Create a transform stream to duplicate the data
  const proxyStream = new Transform({
    transform(chunk, _, end) {
      parseBuffer((message) => {
        const match = message.match(STARTING_SESSION_MESSAGE);
        if (match) {
          options.onSessionStart?.();
        }

        if (!options?.suppressStartSessionMessage || !match) {
          // Pass the original chunk through to the terminal
          this.push(chunk);
        }

        end();
      })(chunk);
    },
  });

  // Ensures that content from the child process is printed to the terminal and the proxy stream
  childProcess.stdout.pipe(proxyStream).pipe(process.stdout);

  return {
    close: () => {
      proxyStream.destroy();
    },
  };
};

/** Starts an SSM session in the terminal by spawning `aws ssm` as a subprocess
 *
 * Requires `aws ssm` to be installed on the client machine.
 */
const spawnSsmNode = async (options: {
  credentials: AwsCredentials;
  command: string[];
  attemptsRemaining?: number;
  subcommand?: string[];
}): Promise<number | null> =>
  new Promise((resolve, reject) => {
    const child = spawn("/usr/bin/env", options.command, {
      env: {
        ...process.env,
        ...options.credentials,
      },
      stdio: ["inherit", "pipe", "pipe"],
    });

    const subprocesses = subcommandLauncher(options.credentials);

    const stream = interceptSessionOutput(child, {
      onSessionStart() {
        const subcommand = options?.subcommand ?? [];
        if (subcommand.length) {
          subprocesses.executeCommand(subcommand);
        }
      },
    });

    const cleanUpResources = () => {
      subprocesses.killProcesses();
      stream.close();
      print2("SSH session terminated");
    };

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
        spawnSsmNode({
          ...options,
          attemptsRemaining: attemptsRemaining - 1,
        })
          .then((code) => resolve(code))
          .catch(reject);
        return;
      }

      cleanUpResources();
      resolve(code);
    });

    // Ensure that the child process is killed when the parent process is terminated by pressing Ctrl+C
    process.on("SIGINT", () => {
      cleanUpResources();
      process.exit();
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

  const credentials = await assumeRoleWithOktaSaml(authn, {
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
  await spawnSsmNode({
    credentials,
    ...createSsmCommands(ssmArgs),
  });
};
