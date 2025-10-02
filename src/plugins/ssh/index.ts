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
  SshProxyCommandArgs,
} from "../../commands/shared/ssh";
import { PRIVATE_KEY_PATH } from "../../common/keys";
import { auditSshSessionActivity } from "../../drivers/api";
import { getContactMessage } from "../../drivers/config";
import { print2 } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import {
  AccessPattern,
  SshHostKeyInfo,
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
import { randomUUID } from "node:crypto";
import { Readable } from "node:stream";

const RETRY_DELAY_MS = 5000;

const AUTHENTICATION_SUCCESS_PATTERN =
  /Authenticated to [^\s]+ \(via proxy\) using "publickey"/;

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

  const stderrHandler = (chunk: Buffer) => {
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
  };

  child.stderr.on("data", stderrHandler);

  return {
    isAccessPropagated: () =>
      !isEphemeralAccessDeniedException &&
      (!validAccessPatterns || isValidError),
    isLoginException: () => isLoginException,
    cleanup: () => {
      child.stderr.removeListener("data", stderrHandler);
    },
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
      if (!isPreTest && AUTHENTICATION_SUCCESS_PATTERN.test(line)) {
        // We want to let the user know that they successfully authenticated
        print2(line);
        options.audit?.("start");
      } else if (!isPreTest && line.includes("port forwarding failed")) {
        // We also want to let the user know if port forwarding failed
        print2(line);
      }
    }
  }
};

type SpawnSshNodeOptions = {
  credential?: AwsCredentials;
  command: string;
  args: string[];
  endTime: number;
  abortController?: AbortController;
  stdio: [StdioNull, StdioNull, StdioPipe];
  provider: SupportedSshProvider;
  debug?: boolean;
  isAccessPropagationPreTest?: boolean;
  audit?: (action: "end" | "start") => void;
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
      const remaining = ((options.endTime - Date.now()) / 1e3).toFixed(1);
      print2(
        `Waiting for access to propagate. ${gerund} SSH session... (will wait up to ${remaining} seconds)`
      );
    }

    const child = spawn(options.command, options.args, {
      env: {
        ...process.env,
        ...options.credential,
      },
      stdio: options.stdio,
      shell: false,
    });

    // Make sure if the parent process is killed, we kill the child process too
    const signalHandlers = new Map<string, () => void>();
    ["exit", "SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"].forEach((signal) => {
      const handler = () => {
        try {
          child.kill();
        } catch {
          // Ignore errors
        }
        // Resolving the promise so that we don't hang the process forever.
        resolve(0);
      };
      signalHandlers.set(signal, handler);
      process.on(signal, handler);
    });

    // TODO ENG-2284 support login with Google Cloud: currently return a boolean to indicate if the exception was a Google login error.
    const {
      isAccessPropagated,
      isLoginException,
      cleanup: cleanupStderr,
    } = accessPropagationGuard(
      provider.unprovisionedAccessPatterns,
      options.isAccessPropagationPreTest
        ? provider.provisionedAccessPatterns
        : undefined,
      provider.loginRequiredPattern,
      child,
      options
    );

    const onAbort = () =>
      reject(options.abortController?.signal.reason ?? "SSH session aborted");

    options.abortController?.signal.addEventListener("abort", onAbort);

    const cleanupAllListeners = () => {
      // Remove process signal handlers
      signalHandlers.forEach((handler, signal) => {
        process.removeListener(signal, handler);
      });
      // Remove abort listener
      options.abortController?.signal.removeEventListener("abort", onAbort);
      // Remove stderr data listener
      cleanupStderr();
    };

    const exitListener = child.on("exit", (code) => {
      exitListener.unref();
      cleanupAllListeners();

      // In the case of ephemeral AccessDenied exceptions due to unpropagated
      // permissions, continually retry access until success
      if (!isAccessPropagated()) {
        if (options.endTime < Date.now()) {
          reject(
            `Access did not propagate through ${provider.friendlyName} in time. ${getContactMessage()}`
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

      if (!options.isAccessPropagationPreTest) {
        options.audit?.("end");
        print2(`SSH session terminated`);
      }

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
  request: SshRequest,
  args: CommandArgs,
  setupData: SshAdditionalSetup | undefined,
  proxyCommand: string[],
  sshHostKeys: SshHostKeyInfo
) => {
  addCommonArgs(args, proxyCommand, setupData, sshHostKeys);

  const sshOptionsOverrides = setupData?.sshOptions ?? [];
  const port = setupData?.port;

  const argsOverride = sshOptionsOverrides.flatMap((opt) => ["-o", opt]);

  if ("source" in args) {
    addScpArgs(args);

    return {
      command: "scp" as const,
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
    command: "ssh" as const,
    args: [
      ...(args.sshOptions ? args.sshOptions : []),
      ...argsOverride,
      ...(port ? ["-p", port] : []),
      `${request.linuxUserName}@${request.id}`,
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
  setupData: SshAdditionalSetup | undefined,
  sshHostKeys: SshHostKeyInfo
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

  const userKnownHostsFileOptionExists = sshOptions.some(
    (opt, idx) =>
      opt === "-o" && sshOptions[idx + 1]?.startsWith("UserKnownHostsFile")
  );

  if (sshHostKeys && !userKnownHostsFileOptionExists) {
    sshOptions.push("-o", `UserKnownHostsFile=${sshHostKeys.path}`);
  }

  const hostKeyAliasOptionExists = sshOptions.some(
    (opt, idx) =>
      opt === "-o" && sshOptions[idx + 1]?.startsWith("HostKeyAlias")
  );

  if (sshHostKeys && !hostKeyAliasOptionExists)
    sshOptions.push("-o", `HostKeyAlias=${sshHostKeys.alias}`);

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
  if (!recursiveOptionExists) {
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
  endTime: number,
  abortController: AbortController,
  sshHostKeys: SshHostKeyInfo
) => {
  const testCmdArgs = sshProvider.preTestAccessPropagationArgs(cmdArgs);

  // Pre-testing comes at a performance cost because we have to execute another ssh subprocess after
  // a successful test. Only do when absolutely necessary.
  if (testCmdArgs) {
    const { command, args } = createCommand(
      request,
      testCmdArgs,
      setupData,
      proxyCommand,
      sshHostKeys
    );
    // Assumes that this is a non-interactive ssh command that exits automatically
    return spawnSshNode({
      credential,
      abortController,
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
  requestId: string;
  cmdArgs: CommandArgs;
  privateKey: string;
  sshProvider: SshProvider<any, any, any, any>;
  sshHostKeys: SshHostKeyInfo;
}) => {
  const sshSessionId = randomUUID();
  const {
    authn,
    request,
    requestId,
    cmdArgs,
    privateKey,
    sshProvider,
    sshHostKeys,
  } = args;
  const { debug } = cmdArgs;

  if (!privateKey) {
    throw `Failed to load a private key for this request. ${getContactMessage()}`;
  }

  const abortController = new AbortController();

  const credential: AwsCredentials | undefined =
    await sshProvider.cloudProviderLogin(authn, request, debug);

  const setupData = await sshProvider.setup?.(authn, request, {
    requestId,
    abortController,
    debug,
  });

  const proxyCommand = sshProvider.proxyCommand(request, setupData?.port);

  const { command, args: commandArgs } = createCommand(
    request,
    cmdArgs,
    setupData,
    proxyCommand,
    sshHostKeys
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
      endTime,
      abortController,
      sshHostKeys
    );
    if (exitCode && exitCode !== 0) {
      return exitCode; // Only exit if there was an error when pre-testing
    }

    return await spawnSshNode({
      audit: (action) =>
        void auditSshSessionActivity({
          authn,
          requestId,
          sshSessionId,
          debug,
          action: `ssh.session.${action}`,
        }),
      credential,
      abortController,
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

export const sshProxy = async (args: {
  authn: Authn;
  request: SshRequest;
  requestId: string;
  cmdArgs: SshProxyCommandArgs;
  privateKey: string;
  sshProvider: SshProvider<any, any, any, any>;
  debug: boolean;
  port: string;
}) => {
  const { authn, sshProvider, request, requestId, debug } = args;

  const credential: AwsCredentials | undefined =
    await sshProvider.cloudProviderLogin(authn, request);

  const abortController = new AbortController();

  const setupData = await sshProvider.setupProxy?.(request, {
    debug,
    abortController,
  });

  const proxyCommand = sshProvider.proxyCommand(
    request,
    setupData?.port ?? args.port
  );

  const command = proxyCommand[0];
  if (!command) {
    throw "This provider does not support running as a ProxyCommand";
  }

  const proxyArgs = proxyCommand.slice(1);

  const endTime = Date.now() + sshProvider.propagationTimeoutMs;

  const auditArgs = {
    authn,
    requestId,
    debug,
    sshSessionId: randomUUID(),
  };

  try {
    // ssh-proxy doesn't do any pre-test propagation and can't intercept
    // messages from the parent ssh command making it impossible for us
    // to check for stdout/stderr for session start/end messages.
    void auditSshSessionActivity({
      ...auditArgs,
      action: `ssh.session.start`,
    });
    return await spawnSshNode({
      credential,
      abortController,
      command,
      args: proxyArgs,
      stdio: ["inherit", "inherit", "pipe"],
      debug,
      provider: request.type,
      endTime: endTime,
    });
  } finally {
    await auditSshSessionActivity({
      ...auditArgs,
      action: `ssh.session.end`,
    });
    await setupData?.teardown();
  }
};
