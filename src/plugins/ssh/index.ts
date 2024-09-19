/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { CommandArgs, SSH_PROVIDERS } from "../../commands/shared/ssh";
import { PRIVATE_KEY_PATH } from "../../common/keys";
import { print2 } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import { SshProvider, SshRequest, SupportedSshProvider } from "../../types/ssh";
import { AwsCredentials } from "../aws/types";
import {
  ChildProcessByStdio,
  StdioNull,
  StdioPipe,
  spawn,
} from "node:child_process";
import { Readable } from "node:stream";

/** Matches the error message that AWS SSM print1 when access is not propagated */
// Note that the resource will randomly be either the SSM document or the EC2 instance
const UNAUTHORIZED_START_SESSION_MESSAGE =
  /An error occurred \(AccessDeniedException\) when calling the StartSession operation: User: arn:aws:sts::.*:assumed-role\/P0GrantsRole.* is not authorized to perform: ssm:StartSession on resource: arn:aws:.*:.*:.* because no identity-based policy allows the ssm:StartSession action/;
/**
 * Matches the following error messages that AWS SSM print1 when ssh authorized
 * key access hasn't propagated to the instance yet.
 * - Connection closed by UNKNOWN port 65535
 * - scp: Connection closed
 * - kex_exchange_identification: Connection closed by remote host
 */
const CONNECTION_CLOSED_MESSAGE =
  /\bConnection closed\b.*\b(?:by UNKNOWN port \d+|by remote host)?/;
const PUBLIC_KEY_DENIED_MESSAGE = /Permission denied \(publickey\)/;
const UNAUTHORIZED_TUNNEL_USER_MESSAGE =
  /Error while connecting \[4033: 'not authorized'\]/;
const UNAUTHORIZED_INSTANCES_GET_MESSAGE =
  /Required 'compute\.instances\.get' permission/;
const DESTINATION_READ_ERROR =
  /Error while connecting \[4010: 'destination read failed'\]/;
const GOOGLE_LOGIN_MESSAGE =
  /You do not currently have an active account selected/;
const SUDO_MESSAGE = /Sorry, user .+ may not run sudo on .+/; // The output of `sudo -v` when the user is not allowed to run sudo

/** Maximum amount of time after SSH subprocess starts to check for {@link UNPROVISIONED_ACCESS_MESSAGES}
 *  in the process's stderr
 */
const DEFAULT_VALIDATION_WINDOW_MS = 5e3;

const RETRY_DELAY_MS = 3000;

/**
 * AWS
 * There are 2 cases of unprovisioned access in AWS
 * 1. SSM:StartSession action is missing either on the SSM document (AWS-StartSSHSession) or the EC2 instance
 * 2. Temporary error when issuing an SCP command
 *
 * 1: results in UNAUTHORIZED_START_SESSION_MESSAGE
 * 2: results in CONNECTION_CLOSED_MESSAGE
 *
 * Google Cloud
 * There are 7 cases of unprovisioned access in Google Cloud.
 * These are all potentially subject to propagation delays.
 * 1. The linux user name is not present in the user's Google Workspace profile `posixAccounts` attribute
 * 2. The public key is not present in the user's Google Workspace profile `sshPublicKeys` attribute
 * 3. The user cannot act as the service account of the compute instance
 * 4. The user cannot tunnel through the IAP tunnel to the instance
 * 5. The user doesn't have osLogin or osAdminLogin role to the instance
 * 5.a. compute.instances.get permission is missing
 * 5.b. compute.instances.osLogin permission is missing
 * 6. compute.instances.osAdminLogin is not provisioned but compute.instances.osLogin is - happens when a user upgrades existing access to sudo
 * 7: Rare occurrence, the exact conditions so far undetermined (together with CONNECTION_CLOSED_MESSAGE)
 *
 * 1, 2, 3 (yes!), 5b: result in PUBLIC_KEY_DENIED_MESSAGE
 * 4: results in UNAUTHORIZED_TUNNEL_USER_MESSAGE and also CONNECTION_CLOSED_MESSAGE
 * 5a: results in UNAUTHORIZED_INSTANCES_GET_MESSAGE
 * 6: results in SUDO_MESSAGE
 * 7: results in DESTINATION_READ_ERROR and also CONNECTION_CLOSED_MESSAGE
 */
const UNPROVISIONED_ACCESS_MESSAGES = [
  { pattern: UNAUTHORIZED_START_SESSION_MESSAGE },
  { pattern: CONNECTION_CLOSED_MESSAGE },
  { pattern: PUBLIC_KEY_DENIED_MESSAGE },
  { pattern: SUDO_MESSAGE },
  { pattern: UNAUTHORIZED_TUNNEL_USER_MESSAGE },
  { pattern: UNAUTHORIZED_INSTANCES_GET_MESSAGE, validationWindowMs: 30e3 },
  { pattern: DESTINATION_READ_ERROR },
];

/** Checks if access has propagated through AWS to the SSM agent
 *
 * AWS takes about 8 minutes, GCP takes under 1 minute
 * to fully resolve access after it is granted.
 * During this time, calls to `aws ssm start-session` / `gcloud compute start-iap-tunnel`
 * will fail randomly with an various error messages.
 *
 * This function checks the subprocess output to see if any of the error messages
 * are printed to the error output within the first 5 seconds of startup.
 * If they are, the returned `isAccessPropagated()` function will return false.
 * When this occurs, the consumer of this function should retry the `aws` / `gcloud` command.
 *
 * Note that this function requires interception of the subprocess stderr stream.
 * This works because AWS SSM wraps the session in a single-stream pty, so we
 * do not capture stderr emitted from the wrapped shell session.
 */
const accessPropagationGuard = (
  child: ChildProcessByStdio<null, null, Readable>,
  debug?: boolean
) => {
  let isEphemeralAccessDeniedException = false;
  let isGoogleLoginException = false;
  const beforeStart = Date.now();

  child.stderr.on("data", (chunk) => {
    const chunkString: string = chunk.toString("utf-8");

    if (debug) print2(chunkString);

    const match = UNPROVISIONED_ACCESS_MESSAGES.find((message) =>
      chunkString.match(message.pattern)
    );

    if (
      match &&
      Date.now() <=
        beforeStart + (match.validationWindowMs || DEFAULT_VALIDATION_WINDOW_MS)
    ) {
      isEphemeralAccessDeniedException = true;
    }

    const googleLoginMatch = chunkString.match(GOOGLE_LOGIN_MESSAGE);
    isGoogleLoginException = isGoogleLoginException || !!googleLoginMatch; // once true, always true
    if (isGoogleLoginException) {
      isEphemeralAccessDeniedException = false; // always overwrite to false so we don't retry the access
    }
  });

  return {
    isAccessPropagated: () => !isEphemeralAccessDeniedException,
    isGoogleLoginException: () => isGoogleLoginException,
  };
};

const spawnChildProcess = (
  credential: AwsCredentials | undefined,
  command: string,
  args: string[],
  stdio: [StdioNull, StdioNull, StdioPipe]
) =>
  spawn(command, args, {
    env: {
      ...process.env,
      ...credential,
    },
    stdio,
    shell: false,
  });

type SpawnSshNodeOptions = {
  credential?: AwsCredentials;
  command: string;
  args: string[];
  attemptsRemaining: number;
  abortController?: AbortController;
  detached?: boolean;
  stdio: [StdioNull, StdioNull, StdioPipe];
  provider: SupportedSshProvider;
  debug?: boolean;
  isAccessPropagationPreTest?: boolean;
};

/** Starts an SSM session in the terminal by spawning `aws ssm` as a subprocess
 *
 * Requires `aws ssm` to be installed on the client machine.
 */

async function spawnSshNode(
  options: SpawnSshNodeOptions
): Promise<number | null> {
  return new Promise((resolve, reject) => {
    const provider = SSH_PROVIDERS[options.provider];

    const attemptsRemaining = options.attemptsRemaining;
    if (options.debug) {
      const gerund = options.isAccessPropagationPreTest
        ? "Pre-testing"
        : "Trying";
      print2(
        `Waiting for access to propagate. ${gerund} SSH session... (remaining attempts: ${attemptsRemaining})`
      );
    }

    const child = spawnChildProcess(
      options.credential,
      options.command,
      options.args,
      options.stdio
    );

    // TODO ENG-2284 support login with Google Cloud: currently return a boolean to indicate if the exception was a Google login error.
    const { isAccessPropagated, isGoogleLoginException } =
      accessPropagationGuard(child, options.debug);

    const exitListener = child.on("exit", (code) => {
      exitListener.unref();
      // In the case of ephemeral AccessDenied exceptions due to unpropagated
      // permissions, continually retry access until success
      if (!isAccessPropagated()) {
        if (attemptsRemaining <= 0) {
          reject(
            `Access did not propagate through ${provider.friendlyName} before max retry attempts were exceeded. Please contact support@p0.dev for assistance.`
          );
          return;
        }

        delay(RETRY_DELAY_MS).then(() =>
          spawnSshNode({
            ...options,
            attemptsRemaining: attemptsRemaining - 1,
          })
            .then((code) => resolve(code))
            .catch(reject)
        );

        return;
      } else if (isGoogleLoginException()) {
        reject(`Please login to Google Cloud CLI with 'gcloud auth login'`);
        return;
      }

      options.abortController?.abort(code);
      if (!options.isAccessPropagationPreTest) print2(`SSH session terminated`);
      resolve(code);
    });
  });
}

const createCommand = (
  data: SshRequest,
  args: CommandArgs,
  proxyCommand: string[]
) => {
  const commonArgs = [
    ...(args.debug ? ["-v"] : []),
    // Explicitly specify which private key to use to avoid "Too many authentication failures"
    // error caused by SSH trying every available key
    "-i",
    PRIVATE_KEY_PATH,
    // Only use the authentication identity specified by -i above
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    `ProxyCommand=${proxyCommand.join(" ")}`,
  ];

  if ("source" in args) {
    return {
      command: "scp",
      args: [
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
      ],
    };
  }

  return {
    command: "ssh",
    args: [
      ...commonArgs,
      ...(args.A ? ["-A"] : []),
      ...(args.L ? ["-L", args.L] : []),
      ...(args.R ? ["-R", args.R] : []),
      ...(args.N ? ["-N"] : []),
      ...(args.o ? ["-o", args.o] : []),
      `${data.linuxUserName}@${data.id}`,
      ...(args.command ? [args.command] : []),
      ...args.arguments.map(
        (argument) =>
          // escape all double quotes (") in commands such as `p0 ssh <instance>> echo 'hello; "world"'` because we
          // need to encapsulate command arguments in double quotes as we pass them along to the remote shell
          `"${String(argument).replace(/"/g, '\\"')}"`
      ),
    ],
  };
};

/** Converts arguments for manual execution - arguments may have to be quoted or certain characters escaped when executing the commands from a shell */
const transformForShell = (args: string[]) => {
  return args.map((arg) => {
    // The ProxyCommand option must be surrounded by single quotes
    if (arg.startsWith("ProxyCommand=")) {
      const [name, ...value] = arg.split("="); // contains the '=' character in the parameters option: ProxyCommand=aws ssm start-session ... --parameters "portNumber=%p"
      return `${name}='${value.join("=")}'`;
    }
    return arg;
  });
};

/** Construct another command to use for testing access propagation prior to actually logging in the user to the ssh session */
const preTestAccessPropagationIfNeeded = async <
  P extends SshProvider<any, any, any, any>,
>(
  sshProvider: P,
  request: SshRequest,
  cmdArgs: CommandArgs,
  proxyCommand: string[],
  credential: P extends SshProvider<infer _PR, infer _O, infer _SR, infer C>
    ? C
    : undefined
) => {
  const testCmdArgs = sshProvider.preTestAccessPropagationArgs(cmdArgs);
  // Pre-testing comes at a performance cost because we have to execute another ssh subprocess after
  // a successful test. Only do when absolutely necessary.
  if (testCmdArgs) {
    const { command, args } = createCommand(request, testCmdArgs, proxyCommand);
    // Assumes that this is a non-interactive ssh command that exits automatically
    return spawnSshNode({
      credential,
      abortController: new AbortController(),
      command,
      args,
      stdio: ["inherit", "inherit", "pipe"],
      debug: cmdArgs.debug,
      provider: request.type,
      attemptsRemaining: sshProvider.maxRetries,
      isAccessPropagationPreTest: true,
    });
  }
  return null;
};

export const sshOrScp = async (args: {
  authn: Authn;
  request: SshRequest;
  cmdArgs: CommandArgs;
  privateKey: string;
  sshProvider: SshProvider<any, any, any, any>;
}) => {
  const { authn, request, cmdArgs, privateKey, sshProvider } = args;
  if (!privateKey) {
    throw "Failed to load a private key for this request. Please contact support@p0.dev for assistance.";
  }

  const credential: AwsCredentials | undefined =
    await sshProvider.cloudProviderLogin(authn, request);

  const proxyCommand = sshProvider.proxyCommand(request);

  const { command, args: commandArgs } = createCommand(
    request,
    cmdArgs,
    proxyCommand
  );

  if (cmdArgs.debug) {
    const reproCommands = sshProvider.reproCommands(request);
    if (reproCommands) {
      const repro = [
        ...reproCommands,
        `${command} ${transformForShell(commandArgs).join(" ")}`,
      ].join("\n");
      print2(
        `Execute the following commands to create a similar SSH/SCP session:\n*** COMMANDS BEGIN ***\n${repro}\n*** COMMANDS END ***"\n`
      );
    }
  }

  const exitCode = await preTestAccessPropagationIfNeeded(
    sshProvider,
    request,
    cmdArgs,
    proxyCommand,
    credential
  );
  if (exitCode && exitCode !== 0) {
    return exitCode; // Only exit if there was an error when pre-testing
  }

  return spawnSshNode({
    credential,
    abortController: new AbortController(),
    command,
    args: commandArgs,
    stdio: ["inherit", "inherit", "pipe"],
    debug: cmdArgs.debug,
    provider: request.type,
    attemptsRemaining: sshProvider.maxRetries,
  });
};

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
