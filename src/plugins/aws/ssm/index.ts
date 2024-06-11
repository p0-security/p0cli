/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  ExerciseGrantResponse,
  ScpCommandArgs,
  SshCommandArgs,
} from "../../../commands/shared";
import { print2 } from "../../../drivers/stdio";
import { Authn } from "../../../types/identity";
import { assumeRoleWithOktaSaml } from "../../okta/aws";
import { AwsCredentials } from "../types";
import { ensureSsmInstall } from "./install";
import { without } from "lodash";
import {
  ChildProcess,
  ChildProcessByStdio,
  StdioNull,
  StdioPipe,
  exec,
  spawn,
} from "node:child_process";
import { Readable, Transform, Writable } from "node:stream";
import psTree from "ps-tree";

const STARTING_SESSION_MESSAGE = /Starting session with SessionId: (.*)/;

/** Matches the error message that AWS SSM print1 when access is not propagated */
// Note that the resource will randomly be either the SSM document or the EC2 instance
const UNPROVISIONED_ACCESS_MESSAGE =
  /An error occurred \(AccessDeniedException\) when calling the StartSession operation: User: arn:aws:sts::.*:assumed-role\/P0GrantsRole.* is not authorized to perform: ssm:StartSession on resource: arn:aws:.*:.*:.* because no identity-based policy allows the ssm:StartSession action/;
/**
 * Matches the following error messages that AWS SSM print1 when ssh authorized
 * key access hasn't propagated to the instance yet.
 * - Connection closed by UNKNOWN port 65535
 * - scp: Connection closed
 * - kex_exchange_identification: Connection closed by remote host
 */
const UNPROVISIONED_SCP_ACCESS_MESSAGE =
  /\bConnection closed\b.*\b(?:by UNKNOWN port \d+|by remote host)?/;
/** Maximum amount of time after AWS SSM process starts to check for {@link UNPROVISIONED_ACCESS_MESSAGE}
 *  in the process's stderr
 */
const UNPROVISIONED_ACCESS_VALIDATION_WINDOW_MS = 5e3;

/** Maximum number of attempts to start an SSM session
 *
 * Note that each attempt consumes ~ 1 s.
 */
const MAX_SSM_RETRIES = 30;

/** The name of the SessionManager port forwarding document. This document is managed by AWS.  */
const LOCAL_PORT_FORWARDING_DOCUMENT_NAME = "AWS-StartPortForwardingSession";
const START_SSH_SESSION_DOCUMENT_NAME = "AWS-StartSSHSession";

type SsmArgs = {
  instance: string;
  region: string;
  requestId: string;
  documentName: string;
  command?: string;
  forwardPortAddress?: string;
  noRemoteCommands?: boolean;
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
 * do not capture stderr emitted from the wrapped shell session.
 */
const accessPropagationGuard = (
  child: ChildProcessByStdio<any, any, Readable>
) => {
  let isEphemeralAccessDeniedException = false;
  const beforeStart = Date.now();

  child.stderr.on("data", (chunk) => {
    const chunkString = chunk.toString("utf-8");
    const match =
      chunkString.match(UNPROVISIONED_ACCESS_MESSAGE) ||
      chunkString.match(UNPROVISIONED_SCP_ACCESS_MESSAGE);

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

const createBaseSsmCommand = (args: Pick<SsmArgs, "instance" | "region">) => {
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

const createInteractiveShellCommand = (
  args: Omit<SsmArgs, "forwardPortAddress" | "requestId">
) => {
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

type SsmCommands = { shellCommand: string[]; subCommand?: string[] };

const createSsmCommands = (args: Omit<SsmArgs, "requestId">): SsmCommands => {
  const interactiveShellCommand = createInteractiveShellCommand(args);

  const forwardPortAddress = args.forwardPortAddress;
  if (!forwardPortAddress) {
    return { shellCommand: interactiveShellCommand };
  }

  const portForwardingCommand = createPortForwardingCommand({
    ...args,
    forwardPortAddress,
  });

  if (args.noRemoteCommands) {
    return { shellCommand: portForwardingCommand };
  }

  return {
    shellCommand: interactiveShellCommand,
    subCommand: portForwardingCommand,
  };
};

function spawnChildProcess(
  credential: AwsCredentials,
  command: string,
  args: string[],
  stdio: [StdioNull, StdioPipe, StdioPipe],
  shell: boolean
): ChildProcessByStdio<null, Readable, Readable>;
function spawnChildProcess(
  credential: AwsCredentials,
  command: string,
  args: string[],
  stdio: [StdioNull, StdioNull, StdioPipe],
  shell: boolean
): ChildProcessByStdio<null, null, Readable>;
function spawnChildProcess(
  credential: AwsCredentials,
  command: string,
  args: string[],
  stdio: [StdioPipe, StdioNull, StdioPipe],
  shell: boolean
): ChildProcessByStdio<Writable, null, Readable>;
function spawnChildProcess(
  credential: AwsCredentials,
  command: string,
  args: string[],
  stdio: [StdioNull | StdioPipe, StdioNull, StdioPipe],
  shell: boolean
):
  | ChildProcessByStdio<null, null, Readable>
  | ChildProcessByStdio<Writable, null, Readable>;
function spawnChildProcess(
  credential: AwsCredentials,
  command: string,
  args: string[],
  stdio: [StdioNull | StdioPipe, StdioNull | StdioPipe, StdioPipe],
  shell: boolean
):
  | ChildProcess
  | ChildProcessByStdio<null, null, null>
  | ChildProcessByStdio<null, Readable, Readable>
  | ChildProcessByStdio<Writable, null, Readable> {
  return spawn(command, args, {
    env: {
      ...process.env,
      ...credential,
    },
    stdio,
    shell: shell || false,
  });
}

type SpawnSsmNodeOptions = {
  credential: AwsCredentials;
  command: string;
  args: string[];
  attemptsRemaining?: number;
  abortController?: AbortController;
  detached?: boolean;
  stdio: [StdioNull | StdioPipe, StdioNull, StdioPipe];
  shell: boolean;
};

/** Starts an SSM session in the terminal by spawning `aws ssm` as a subprocess
 *
 * Requires `aws ssm` to be installed on the client machine.
 */

async function spawnSsmNode(
  options: SpawnSsmNodeOptions
): Promise<number | null> {
  return new Promise((resolve, reject) => {
    const child = spawnChildProcess(
      options.credential,
      options.command,
      options.args,
      options.stdio,
      options.shell
    );

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

        spawnSsmNode({
          ...options,
          attemptsRemaining: attemptsRemaining - 1,
        })
          .then((code) => resolve(code))
          .catch(reject);
        return;
      }

      options.abortController?.abort(code);
      print2(`SSH session terminated`);
      resolve(code);
    });
  });
}

/**
 * A subprocess SSM session redirects its output through a proxy that filters certain messages reducing the verbosity of the output.
 * The subprocess also makes sure to terminate any grandchild processes that might spawn during the session.
 *
 * This process should be used when multiple SSM sessions need to be spawned in parallel.
 */
const spawnSubprocessSsmNode = async (options: {
  credential: AwsCredentials;
  command: string[];
  attemptsRemaining?: number;
  abortController: AbortController;
}): Promise<number | null> =>
  new Promise((resolve, reject) => {
    const child = spawnChildProcess(
      options.credential,
      "/usr/bin/env",
      options.command,
      ["ignore", "pipe", "pipe"],
      false
    );

    // Captures the starting session message and filters it from the output
    const proxyStream = new Transform({
      transform(chunk, _, end) {
        const message = chunk.toString("utf-8");
        const match = message.match(STARTING_SESSION_MESSAGE);
        if (!match) {
          this.push(chunk);
        }
        end();
      },
    });

    // Ensures that content from the child process is printed to the terminal and the proxy stream
    child.stdout.pipe(proxyStream).pipe(process.stdout);

    const { isAccessPropagated } = accessPropagationGuard(child);

    const abortListener = (code: any) => {
      options.abortController.signal.removeEventListener(
        "abort",
        abortListener
      );

      // AWS CLI typically will spawn a grandchild process for the SSM session. Using `ps-tree` will allow us
      // to identify and terminate the grandchild process as well.
      psTree(child.pid!, function (_, children) {
        // kill the original child process first so that messages from grandchildren are not printed to stdout
        child.kill();
        // Send a SIGTERM because other signals (e.g. SIGKILL) will not propagate to the grandchildren
        exec(`kill -15 ${children.map((p) => p.PID).join(" ")}`);
      });

      resolve(code);
    };

    child.on("spawn", () => {
      options.abortController.signal.addEventListener("abort", abortListener);
    });

    const exitListener = child.on("exit", (code) => {
      exitListener.unref();

      // In the case of ephemeral AccessDenied exceptions due to unpropagated
      // permissions, continually retry access until success
      if (!isAccessPropagated()) {
        options.abortController.signal.removeEventListener(
          "abort",
          abortListener
        );

        const attemptsRemaining = options?.attemptsRemaining ?? MAX_SSM_RETRIES;
        if (attemptsRemaining <= 0) {
          reject(
            "Access did not propagate through AWS before max retry attempts were exceeded. Please contact support@p0.dev for assistance."
          );
          return;
        }

        spawnSubprocessSsmNode({
          ...options,
          attemptsRemaining: attemptsRemaining - 1,
        })
          .then((code) => resolve(code))
          .catch(reject);
        return;
      }

      options.abortController.abort(code);
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
  request: ExerciseGrantResponse,
  args: SshCommandArgs
) => {
  const isInstalled = await ensureSsmInstall();
  if (!isInstalled)
    throw "Please try again after installing the required AWS utilities";
  const credential = await assumeRoleWithOktaSaml(authn, {
    account: request.instance.accountId,
    role: request.role,
  });

  const ssmArgs = {
    instance: request.instance.id,
    region: request.instance.region,
    documentName: request.documentName,
    forwardPortAddress: args.L,
    noRemoteCommands: args.N,
    command: commandParameter(args),
  };

  const ssmCommands = createSsmCommands(ssmArgs);

  await startSsmProcesses(credential, ssmCommands);
};

/**
 * Starts the SSM session and any additional processes that are requested for the session to function properly.
 */
const startSsmProcesses = async (
  credential: AwsCredentials,
  commands: SsmCommands
) => {
  /** The AbortController is responsible for sending a shared signal to all spawned processes ({@link spawnSsmNode}) when the parent process is terminated unexpectedly. This is necessary because the spawned processes are detached and would otherwise continue running after the parent process is terminated. */
  const abortController = new AbortController();

  const args = { credential, abortController };
  const processes: Promise<unknown>[] = [
    spawnSsmNode({
      ...args,
      command: "/usr/bin/env",
      args: commands.shellCommand,
      stdio: ["inherit", "inherit", "pipe"],
      shell: false,
    }),
  ];

  if (commands.subCommand) {
    processes.push(
      spawnSubprocessSsmNode({
        ...args,
        command: commands.subCommand,
      })
    );
  }

  await Promise.all(processes);
};

const createProxyCommands = (
  data: ExerciseGrantResponse,
  args: ScpCommandArgs | SshCommandArgs,
  debug?: boolean
) => {
  const ssmCommand = [
    ...createBaseSsmCommand({
      region: data.instance.region,
      instance: "%h",
    }),
    "--document-name",
    START_SSH_SESSION_DOCUMENT_NAME,
    "--parameters",
    '"portNumber=%p"',
  ];

  const commonArgs = [
    ...(debug ? ["-v"] : []),
    // ignore any overrides in the user's config file, we only want to use the ssh-agent we've set up for the session
    "-o",
    "IdentityAgent=$SSH_AUTH_SOCK",
    "-o",
    `ProxyCommand='${ssmCommand.join(" ")}'`,
  ];

  if ("source" in args) {
    return [
      "scp",
      ...commonArgs,
      // if a response is not received after three 5 minute attempts,
      // the connection will be closed.
      "-o",
      "ServerAliveCountMax=3",
      `-o`,
      "ServerAliveInterval=300",
      ...(args.recursive ? ["-r"] : []),
      args.source,
      args.destination,
    ];
  }

  return [
    "ssh",
    ...commonArgs,
    ...(args.A ? ["-A"] : []),
    `${data.linuxUserName}@${data.instance.id}`,
  ].join(" ");
};

export const sshOrScp = async (
  authn: Authn,
  data: ExerciseGrantResponse,
  args: ScpCommandArgs | SshCommandArgs,
  privateKey: string
) => {
  if (!(await ensureSsmInstall())) {
    throw "Please try again after installing the required AWS utilities";
  }

  if (!privateKey) {
    throw "Failed to load a private key for this request. Please contact support@p0.dev for assistance.";
  }

  const credential = await assumeRoleWithOktaSaml(authn, {
    account: data.instance.accountId,
    role: data.role,
  });

  const command = createProxyCommands(data, args, args.debug);

  const debug = [
    `echo "SSH_AUTH_SOCK: $SSH_AUTH_SOCK"`,
    `echo "SSH_AGENT_PID: $SSH_AGENT_PID"`,
    `echo '$(p0 aws role assume ${data.role})'`,
    `echo "${command}"`,
    `echo "SSH Agent Keys:"`,
    `ssh-add -l`,
  ];

  /**
   * Spawns a child process to add a private key to the ssh-agent. The SSH agent is included in the OpenSSH suite
   * of tools and is used to hold private keys during a session. The SSH agent typically does not persist keys
   * across system reboots or logout/login cycles. Once you log out or restart your system, any keys added to
   * the SSH agent during that session will need to be added again in subsequent sessions.
   */
  const commands = [
    // This might be overkill because we are already spawning a subprocess that will run the commands for us
    // but just in case someone enters that subprocess we're also disabling the history of commands run.
    `unset HISTFILE`,
    // in debug mode, we want to see the pid of the ssh-agent and compare it to the environment variable
    `eval $(ssh-agent)${args.debug ? "" : " >/dev/null 2>&1"}`,
    `trap 'kill $SSH_AGENT_PID' EXIT`,
    `ssh-add -q - <<< '${privateKey}'`,
    // in debug mode, we'll see the keys that were added to the agent and more information about the agent
    ...(args.debug ? debug : []),
    command,
    `SCP_EXIT_CODE=$?`,
    `exit $SCP_EXIT_CODE`,
  ];

  if (args.debug) {
    // Print commands that can be individually executed to reproduce behavior
    // Remove the debug information - can be executed manually between steps
    const reproCommands = without(
      [
        "bash",
        ...Object.entries(process.env).map(
          ([key, value]) => `export ${key}='${value}'`
        ),
        ...Object.entries(credential).map(
          ([key, value]) => `export ${key}='${value}'`
        ),
        ...commands,
      ],
      ...debug
    );
    print2(
      `Execute the following commands to create a similar SCP session:\n *** COMMANDS BEGIN ***\n${reproCommands.join("\n")}\n *** COMMANDS END ***`
    );
  }

  return spawnSsmNode({
    credential,
    abortController: new AbortController(),
    command: commands.join(" && "),
    args: [],
    stdio: ["inherit", "inherit", "pipe"],
    shell: true,
  });
};
