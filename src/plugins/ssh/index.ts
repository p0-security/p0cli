/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  CommandArgs,
  ScpCommandArgs,
  SSH_PROVIDERS,
  SshAdditionalSetup,
} from "../../commands/shared/ssh";
import { PRIVATE_KEY_PATH } from "../../common/keys";
import { print2 } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import {
  AccessPattern,
  SshProvider,
  SshRequest,
  SupportedSshProvider,
} from "../../types/ssh";
import { delay } from "../../util";
import { AwsCredentials } from "../aws/types";
import {
  ChildProcessByStdio,
  StdioNull,
  StdioPipe,
  spawn,
} from "node:child_process";
import { Readable } from "node:stream";

const RETRY_DELAY_MS = 5000;

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
  invalidAccessPatterns: readonly AccessPattern[],
  validAccessPatterns: readonly AccessPattern[] | undefined,
  loginRequiredPattern: RegExp | undefined,
  child: ChildProcessByStdio<null, null, Readable>,
  options: SpawnSshNodeOptions
) => {
  let isEphemeralAccessDeniedException = false;
  let isLoginException = false;
  let isValidError = false;

  child.stderr.on("data", (chunk) => {
    const chunkString: string = chunk.toString("utf-8");
    parseAndPrintSshOutputToStderr(chunkString, options);

    const matchUnprovisionedPattern = invalidAccessPatterns.find((message) =>
      chunkString.match(message.pattern)
    );

    const matchValidAccessPattern = validAccessPatterns?.find((message) =>
      chunkString.match(message.pattern)
    );

    if (matchUnprovisionedPattern) {
      isEphemeralAccessDeniedException = true;
    }

    if (matchValidAccessPattern && !matchUnprovisionedPattern) {
      isValidError = true;
    }

    if (loginRequiredPattern) {
      const loginMatch = chunkString.match(loginRequiredPattern);
      isLoginException = isLoginException || !!loginMatch; // once true, always true
    }

    if (isLoginException) {
      isEphemeralAccessDeniedException = false; // always overwrite to false so we don't retry the access
    }
  });

  return {
    isAccessPropagated: () =>
      !isEphemeralAccessDeniedException &&
      (!validAccessPatterns || isValidError),
    isLoginException: () => isLoginException,
  };
};

/**
 * Parses and prints a chunk of SSH output to stderr.
 *
 * If debug is enabled, all output is printed. Otherwise, only selected messages are printed.
 *
 * @param chunkString the chunk to print
 * @param options SSH spawn options
 */
const parseAndPrintSshOutputToStderr = (
  chunkString: string,
  options: SpawnSshNodeOptions
) => {
  const lines = chunkString.split("\n");
  const isPreTest = options.isAccessPropagationPreTest;

  for (const line of lines) {
    if (options.debug) {
      print2(line);
    } else {
      if (!isPreTest && line.includes("Authenticated to")) {
        // We want to let the user know that they successfully authenticated
        print2(line);
      } else if (!isPreTest && line.includes("port forwarding failed")) {
        // We also want to let the user know if port forwarding failed
        print2(line);
      }
    }
  }
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
  endTime: number;
  abortController?: AbortController;
  detached?: boolean;
  stdio: [StdioNull, StdioNull, StdioPipe];
  provider: SupportedSshProvider;
  debug?: boolean;
  isAccessPropagationPreTest?: boolean;
};

async function spawnSshNode(
  options: SpawnSshNodeOptions
): Promise<number | null> {
  return new Promise((resolve, reject) => {
    const provider = SSH_PROVIDERS[options.provider];

    if (options.debug) {
      const gerund = options.isAccessPropagationPreTest
        ? "Pre-testing"
        : "Trying";
      const remainingSeconds = ((options.endTime - Date.now()) / 1e3).toFixed(
        1
      );
      print2(
        `Waiting for access to propagate. ${gerund} SSH session... (will wait up to ${remainingSeconds} seconds)`
      );
    }

    const child = spawnChildProcess(
      options.credential,
      options.command,
      options.args,
      options.stdio
    );

    // TODO ENG-2284 support login with Google Cloud: currently return a boolean to indicate if the exception was a Google login error.
    const { isAccessPropagated, isLoginException } = accessPropagationGuard(
      provider.unprovisionedAccessPatterns,
      options.isAccessPropagationPreTest
        ? provider.provisionedAccessPatterns
        : undefined,
      provider.loginRequiredPattern,
      child,
      options
    );

    const exitListener = child.on("exit", (code) => {
      exitListener.unref();
      // In the case of ephemeral AccessDenied exceptions due to unpropagated
      // permissions, continually retry access until success
      if (!isAccessPropagated()) {
        if (options.endTime < Date.now()) {
          reject(
            `Access did not propagate through ${provider.friendlyName} in time. Please contact support@p0.dev for assistance.`
          );
          return;
        }

        delay(RETRY_DELAY_MS)
          .then(() => spawnSshNode(options))
          .then((code) => resolve(code))
          .catch(reject);
        return;
      } else if (isLoginException()) {
        reject(
          provider.loginRequiredMessage ??
            `Please log in to the ${provider.friendlyName} CLI to SSH`
        );
        return;
      }

      options.abortController?.abort(code);
      if (!options.isAccessPropagationPreTest) print2(`SSH session terminated`);
      if (options.isAccessPropagationPreTest && isAccessPropagated()) {
        // override the exit code to 0 if the expected error was found, this means access is ready.
        resolve(0);
        return;
      }
      resolve(code);
    });
  });
}

const createCommand = (
  data: SshRequest,
  args: CommandArgs,
  setupData: SshAdditionalSetup | undefined,
  proxyCommand: string[]
) => {
  addCommonArgs(args, proxyCommand, setupData);

  const sshOptionsOverrides = setupData?.sshOptions ?? [];
  const port = setupData?.port;

  const argsOverride = sshOptionsOverrides.flatMap((opt) => ["-o", opt]);

  if ("source" in args) {
    addScpArgs(args);

    return {
      command: "scp",
      args: [
        ...(args.sshOptions ? args.sshOptions : []),
        ...argsOverride,
        ...(port ? ["-P", port] : []),
        args.source,
        args.destination,
      ],
    };
  }

  return {
    command: "ssh",
    args: [
      ...(args.sshOptions ? args.sshOptions : []),
      ...argsOverride,
      ...(port ? ["-p", port] : []),
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

/** Add common args used by both SSH & SCP to args.sshOptions.
 *
 * These common args are only added if they have not been explicitly specified by the end user.
 */
const addCommonArgs = (
  args: CommandArgs,
  sshProviderProxyCommand: string[],
  setupData: SshAdditionalSetup | undefined
) => {
  const sshOptions = args.sshOptions ? args.sshOptions : [];

  const identityFileOptionExists = sshOptions.some(
    (opt, idx) =>
      (opt === "-i" && sshOptions[idx + 1]) ||
      (opt === "-o" && sshOptions[idx + 1]?.startsWith("IdentityFile"))
  );

  const identitiesOnlyOptionExists = sshOptions.some(
    (opt, idx) =>
      opt === "-o" && sshOptions[idx + 1]?.startsWith("IdentitiesOnly")
  );

  // Explicitly specify which private key to use to avoid "Too many authentication failures"
  // error caused by SSH trying every available key
  if (!identityFileOptionExists) {
    sshOptions.push("-i", setupData?.identityFile ?? PRIVATE_KEY_PATH);

    // Only use the authentication identity specified by -i above
    if (!identitiesOnlyOptionExists) {
      sshOptions.push("-o", "IdentitiesOnly=yes");
    }
  }

  const userSpecifiedProxyCommand = sshOptions.some(
    (opt, idx) =>
      opt === "-o" && sshOptions[idx + 1]?.startsWith("ProxyCommand")
  );

  if (!userSpecifiedProxyCommand && sshProviderProxyCommand.length > 0) {
    sshOptions.push("-o", `ProxyCommand=${sshProviderProxyCommand.join(" ")}`);
  }

  // Force verbose output from SSH so we can parse the output
  const verboseOptionExists = sshOptions.some((opt) => opt === "-v");
  if (!verboseOptionExists) {
    sshOptions.push("-v");
  }
};

const addScpArgs = (args: ScpCommandArgs) => {
  const sshOptions = args.sshOptions ? args.sshOptions : [];

  // if a response is not received after three 5 minute attempts,
  // the connection will be closed.
  const serverAliveCountMaxOptionExists = sshOptions.some(
    (opt, idx) =>
      opt === "-o" && sshOptions[idx + 1]?.startsWith("ServerAliveCountMax")
  );

  if (!serverAliveCountMaxOptionExists) {
    sshOptions.push("-o", "ServerAliveCountMax=3");
  }

  const serverAliveIntervalOptionExists = sshOptions.some(
    (opt, idx) =>
      opt === "-o" && sshOptions[idx + 1]?.startsWith("ServerAliveInterval")
  );

  if (!serverAliveIntervalOptionExists) {
    sshOptions.push("-o", "ServerAliveInterval=300");
  }

  const recursiveOptionExists = sshOptions.some((opt) => opt === "-r");
  if (!recursiveOptionExists && args.recursive) {
    sshOptions.push("-r");
  }
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
    : undefined,
  setupData: SshAdditionalSetup | undefined,
  endTime: number
) => {
  const testCmdArgs = sshProvider.preTestAccessPropagationArgs(cmdArgs);

  // Pre-testing comes at a performance cost because we have to execute another ssh subprocess after
  // a successful test. Only do when absolutely necessary.
  if (testCmdArgs) {
    const { command, args } = createCommand(
      request,
      testCmdArgs,
      setupData,
      proxyCommand
    );
    // Assumes that this is a non-interactive ssh command that exits automatically
    return spawnSshNode({
      credential,
      abortController: new AbortController(),
      command,
      args,
      stdio: ["inherit", "inherit", "pipe"],
      debug: cmdArgs.debug,
      provider: request.type,
      endTime: endTime,
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
  const { debug } = cmdArgs;

  if (!privateKey) {
    throw "Failed to load a private key for this request. Please contact support@p0.dev for assistance.";
  }

  const credential: AwsCredentials | undefined =
    await sshProvider.cloudProviderLogin(authn, request);

  const proxyCommand = sshProvider.proxyCommand(request);

  const setupData = await sshProvider.setup?.(request, { debug });

  const { command, args: commandArgs } = createCommand(
    request,
    cmdArgs,
    setupData,
    proxyCommand
  );

  if (debug) {
    const reproCommands = sshProvider.reproCommands(request, setupData);
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

  const endTime = Date.now() + sshProvider.propagationTimeoutMs;

  try {
    const exitCode = await preTestAccessPropagationIfNeeded(
      sshProvider,
      request,
      cmdArgs,
      proxyCommand,
      credential,
      setupData,
      endTime
    );
    if (exitCode && exitCode !== 0) {
      return exitCode; // Only exit if there was an error when pre-testing
    }

    return await spawnSshNode({
      credential,
      abortController: new AbortController(),
      command,
      args: commandArgs,
      stdio: ["inherit", "inherit", "pipe"],
      debug,
      provider: request.type,
      endTime: endTime,
    });
  } finally {
    await setupData?.teardown();
  }
};
