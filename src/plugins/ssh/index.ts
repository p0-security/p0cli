/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  CommandArgs,
  RsyncCommandArgs,
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
import { delay, createCleanChildEnv, getOperatingSystem } from "../../util";
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
 * For rsync commands, we also print progress output.
 *
 * @param chunkString the chunk to print
 * @param options SSH spawn options
 */
const parseAndPrintSshOutputToStderr = (
  chunkString: string,
  options: SpawnSshNodeOptions
) => {
  const isPreTest = options.isAccessPropagationPreTest;
  const isRsync = options.command === "rsync";

  if (isRsync && !isPreTest && !options.debug) {
    // For rsync, we need to handle progress output specially
    // rsync uses carriage returns (\r) to update the same line for progress
    // We'll write directly to stderr to preserve the formatting
    // Filter out only SSH debug messages
    if (!chunkString.startsWith("debug1:") && 
        !chunkString.startsWith("debug2:") && 
        !chunkString.startsWith("debug3:") &&
        !chunkString.trim().startsWith("debug")) {
      // Write directly to stderr to preserve carriage returns and progress formatting
      process.stderr.write(chunkString);
      return;
    }
  }

  // For non-rsync or debug mode, use the original line-by-line parsing
  const lines = chunkString.split("\n");
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
      } else if (isRsync && !isPreTest) {
        // Fallback for rsync if we didn't handle it above
        if (
          !line.startsWith("debug1:") &&
          !line.startsWith("debug2:") &&
          !line.startsWith("debug3:") &&
          !line.trim().startsWith("debug") &&
          line.trim().length > 0
        ) {
          print2(line);
        }
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
        ...createCleanChildEnv(),
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
        if (code !== null && code !== 0) {
          print2(`Command failed with exit code ${code}`);
        } else {
          print2(`SSH session terminated`);
        }
      }

      if (options.isAccessPropagationPreTest && isAccessPropagated()) {
        // override the exit code to 0 if the expected error was found, this means access is ready.
        resolve(0);
        return;
      }

      resolve(code);
    });

    child.on("error", (error: Error) => {
      cleanupAllListeners();
      const commandStr = `${options.command} ${options.args.join(" ")}`;
      reject(`Failed to start process: ${error.message}\nCommand: ${commandStr}`);
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
    // Check if this is rsync or scp
    const isRsync = "_commandType" in args && args._commandType === "rsync";
    if (isRsync) {
      addRsyncArgs(args as RsyncCommandArgs);
      
      // Separate SSH options from rsync options
      // SSH options are those that start with -i, -o, -v, -P, -p, or are -o values
      // Everything else is a rsync option
      const sshOptionsForCommand: string[] = [];
      const rsyncOptions: string[] = [];
      const allOptions = args.sshOptions ? args.sshOptions : [];
      
      let i = 0;
      while (i < allOptions.length) {
        const opt = allOptions[i];
        if (!opt) {
          i += 1;
          continue;
        }
        if (opt === "-i" || opt === "-v" || opt === "-P" || opt === "-p") {
          // SSH option with potential value
          sshOptionsForCommand.push(opt);
          if (opt === "-i" || opt === "-P" || opt === "-p") {
            const nextOpt = allOptions[i + 1];
            if (i + 1 < allOptions.length && nextOpt && !nextOpt.startsWith("-")) {
              sshOptionsForCommand.push(nextOpt);
              i += 2;
            } else {
              i += 1;
            }
          } else {
            i += 1;
          }
        } else if (opt === "-o") {
          // SSH -o option
          sshOptionsForCommand.push(opt);
          const nextOpt = allOptions[i + 1];
          if (i + 1 < allOptions.length && nextOpt) {
            sshOptionsForCommand.push(nextOpt);
            i += 2;
          } else {
            i += 1;
          }
        } else {
          // This is a rsync option
          rsyncOptions.push(opt);
          i += 1;
        }
      }

      // Build SSH command string from SSH options
      const sshCommandString = buildSshCommandStringForRsync(
        sshOptionsForCommand,
        request,
        argsOverride,
        port ?? undefined
      );

      // For rsync's -e option, we need to pass the SSH command as a single string
      // that will be executed by the shell. The format should be: "ssh -i key -o ... user@host"
      // rsync will then execute: ssh -i key -o ... user@host rsync --server ...
      // For rsync's -e option, we need to pass the SSH command as a single string
      // When using spawn with shell: false, we pass it as a single argument
      // rsync will then execute: <ssh-command> rsync --server ...
      // If sudo is requested, we need to tell rsync to use sudo on the remote side
      const finalRsyncOptions = [...rsyncOptions];
      if (args.sudo) {
        // Check if --rsync-path is already specified
        const hasRsyncPath = finalRsyncOptions.some(
          (opt, idx) => opt === "--rsync-path" || (idx > 0 && finalRsyncOptions[idx - 1] === "--rsync-path")
        );
        if (!hasRsyncPath) {
          finalRsyncOptions.push("--rsync-path", "sudo rsync");
        }
      }

      const rsyncArgs = [
        "-e",
        sshCommandString, // This is already a properly escaped string
        ...finalRsyncOptions,
        args.source,
        args.destination,
      ];

      // Debug output for rsync commands
      if (args.debug) {
        print2(`[DEBUG] Rsync command: rsync ${rsyncArgs.map(arg => arg.includes(' ') ? `"${arg}"` : arg).join(" ")}`);
        print2(`[DEBUG] SSH command string: ${sshCommandString}`);
        print2(`[DEBUG] Full rsync args: ${JSON.stringify(rsyncArgs)}`);
      }

      return {
        command: "rsync" as const,
        args: rsyncArgs,
      };
    } else {
      // This is scp
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

  if (getOperatingSystem() === "win") {
    // Explicitly set the MAC algorithms to avoid certain MACs whose
    // Windows OpenSSH implementation is unreliable (e.g. umacs-128-etm@openssh.com)
    sshOptions.push("-o", "MACs=hmac-sha2-256-etm@openssh.com,hmac-sha2-256");
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
  if (!recursiveOptionExists) {
    sshOptions.push("-r");
  }
};

const addRsyncArgs = (args: RsyncCommandArgs) => {
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
};

/** Builds the SSH command string for rsync's -e option.
 *
 * This constructs a command like: ssh -i key -o ProxyCommand='...' -o ... -p port
 * The command string is properly escaped for use in rsync's -e option.
 * 
 * Note: When rsync uses -e, it will extract the host from the destination path
 * and call: ssh ... user@host rsync --server ...
 * So we build the SSH command without the user@host part.
 */
const buildSshCommandStringForRsync = (
  sshOptions: string[],
  _request: SshRequest,
  argsOverride: string[],
  port: string | undefined
): string => {
  const sshArgs: string[] = [];

  // Add all SSH options
  sshArgs.push(...sshOptions);

  // Add override options (from setupData)
  sshArgs.push(...argsOverride);

  // Add port if specified (rsync uses -p for SSH, not -P like scp)
  if (port) {
    sshArgs.push("-p", port);
  }

  // Note: We do NOT add user@host here because rsync's -e option expects
  // just the SSH command, and rsync will handle the destination separately
  // via the source/destination paths. The user@host is already in the destination path.

  // Build the command string
  // For rsync's -e option, we need to pass the SSH command as a single string
  // that can be executed. We'll join the arguments with spaces, but we need
  // to be careful about escaping.
  const commandParts = ["ssh", ...sshArgs];
  
  // For rsync's -e option, we need to properly escape the command string
  // The safest approach is to wrap the entire command in a way that preserves
  // arguments with spaces. We'll use a format that works with shell execution.
  // Since rsync will execute this as: sh -c "ssh ...", we need to escape properly.
  
  // For rsync's -e option, we need to create a command string that can be executed
  // We'll escape each argument properly, only quoting when necessary
  const escapedParts = commandParts.map((part) => {
    // If the part contains spaces, quotes, or special shell characters, wrap it in single quotes
    // and escape any single quotes within it
    if (part.includes(" ") || part.includes("'") || part.includes('"') || part.includes("$") || part.includes("`") || part.includes("\\")) {
      // Replace single quotes with '\'' (end quote, escaped quote, start quote)
      const escaped = part.replace(/'/g, "'\\''");
      return `'${escaped}'`;
    }
    // Simple arguments don't need quoting
    return part;
  });

  // Join with spaces - this creates a command string that can be executed
  return escapedParts.join(" ");
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
    // Always show the command being executed in debug mode
    print2(`Executing: ${command} ${commandArgs.join(" ")}`);
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

    // For rsync, we want to see progress output which goes to stderr
    // We still pipe stderr to filter SSH debug messages but show rsync progress
    const isRsyncCommand = command === "rsync";
    
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
      stdio: ["inherit", "inherit", "pipe"], // stderr piped to filter SSH noise but show rsync progress
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
