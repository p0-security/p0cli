/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  ScpCommandArgs,
  SshCommandArgs,
  AwsSshRequest,
  SshRequest,
  AwsSshRoleRequest,
  AwsSshIdcRequest,
} from "../../commands/shared";
import { PRIVATE_KEY_PATH } from "../../common/keys";
import { print2 } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import { assertNever, throwAssertNever } from "../../util";
import { getAwsConfig } from "../aws/config";
import { assumeRoleWithIdc } from "../aws/idc";
import { ensureSsmInstall } from "../aws/ssm/install";
import { AwsCredentials } from "../aws/types";
import { assumeRoleWithOktaSaml } from "../okta/aws";
import { withSshAgent } from "../ssh-agent";
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

/** Maximum amount of time after SSH subprocess starts to check for {@link UNPROVISIONED_ACCESS_MESSAGES}
 *  in the process's stderr
 */
const DEFAULT_VALIDATION_WINDOW_MS = 5e3;

/** Maximum number of attempts to start an SSH session
 *
 * Note that each attempt consumes ~ 1 s.
 */
const DEFAULT_MAX_SSH_RETRIES = 30;
const GCP_MAX_SSH_RETRIES = 120; // GCP requires more time to propagate access

/** The name of the SessionManager port forwarding document. This document is managed by AWS.  */
const START_SSH_SESSION_DOCUMENT_NAME = "AWS-StartSSHSession";

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
 * There are 5 cases of unprovisioned access in Google Cloud.
 * These are all potentially subject to propagation delays.
 * 1. The linux user name is not present in the user's Google Workspace profile `posixAccounts` attribute
 * 2. The public key is not present in the user's Google Workspace profile `sshPublicKeys` attribute
 * 3. The user cannot act as the service account of the compute instance
 * 4. The user cannot tunnel through the IAP tunnel to the instance
 * 5. The user doesn't have osLogin or osAdminLogin role to the instance
 * 5.a. compute.instances.get permission is missing
 * 5.b. compute.instances.osLogin permission is missing
 * 6: Rare occurrence, the exact conditions so far undetermined (together with CONNECTION_CLOSED_MESSAGE)
 *
 * 1, 2, 3 (yes!), 5b: result in PUBLIC_KEY_DENIED_MESSAGE
 * 4: results in UNAUTHORIZED_TUNNEL_USER_MESSAGE and also CONNECTION_CLOSED_MESSAGE
 * 5a: results in UNAUTHORIZED_INSTANCES_GET_MESSAGE
 * 6: results in DESTINATION_READ_ERROR and also CONNECTION_CLOSED_MESSAGE
 */
const UNPROVISIONED_ACCESS_MESSAGES = [
  { pattern: UNAUTHORIZED_START_SESSION_MESSAGE },
  { pattern: CONNECTION_CLOSED_MESSAGE },
  { pattern: PUBLIC_KEY_DENIED_MESSAGE },
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
  provider: "aws" | "gcloud";
  debug?: boolean;
};

const friendlyProvider = (provider: "aws" | "gcloud") =>
  provider === "aws"
    ? "AWS"
    : provider === "gcloud"
      ? "Google Cloud"
      : throwAssertNever(provider);

/** Starts an SSM session in the terminal by spawning `aws ssm` as a subprocess
 *
 * Requires `aws ssm` to be installed on the client machine.
 */

async function spawnSshNode(
  options: SpawnSshNodeOptions
): Promise<number | null> {
  return new Promise((resolve, reject) => {
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
        const attemptsRemaining = options.attemptsRemaining;
        if (options.debug) {
          print2(
            `Waiting for access to propagate. Retrying SSH session... (remaining attempts: ${attemptsRemaining})`
          );
        }
        if (attemptsRemaining <= 0) {
          reject(
            `Access did not propagate through ${friendlyProvider(options.provider)} before max retry attempts were exceeded. Please contact support@p0.dev for assistance.`
          );
          return;
        }

        spawnSshNode({
          ...options,
          attemptsRemaining: attemptsRemaining - 1,
        })
          .then((code) => resolve(code))
          .catch(reject);
        return;
      } else if (isGoogleLoginException()) {
        reject(`Please login to Google Cloud CLI with 'gcloud auth login'`);
        return;
      }

      options.abortController?.abort(code);
      print2(`SSH session terminated`);
      resolve(code);
    });
  });
}

const createProxyCommands = (
  data: SshRequest,
  args: ScpCommandArgs | SshCommandArgs,
  debug?: boolean
) => {
  let proxyCommand;
  if (data.type === "aws") {
    proxyCommand = [
      "aws",
      "ssm",
      "start-session",
      "--region",
      data.region,
      "--target",
      "%h",
      "--document-name",
      START_SSH_SESSION_DOCUMENT_NAME,
      "--parameters",
      '"portNumber=%p"',
    ];
  } else if (data.type === "gcloud") {
    proxyCommand = [
      "gcloud",
      "compute",
      "start-iap-tunnel",
      data.id,
      "%p",
      // --listen-on-stdin flag is required for interactive SSH session.
      // It is undocumented on page https://cloud.google.com/sdk/gcloud/reference/compute/start-iap-tunnel
      // but mention on page https://cloud.google.com/iap/docs/tcp-by-host
      // and also found in `gcloud ssh --dry-run` output
      "--listen-on-stdin",
      `--zone=${data.zone}`,
      `--project=${data.projectId}`,
    ];
  } else {
    throw assertNever(data);
  }

  const commonArgs = [
    ...(debug ? ["-v"] : []),
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
      ...(args.N ? ["-N"] : []),
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

const awsLogin = async (authn: Authn, data: AwsSshRequest) => {
  if (!(await ensureSsmInstall())) {
    throw "Please try again after installing the required AWS utilities";
  }

  const { config } = await getAwsConfig(authn, data.accountId);
  if (!config.login?.type || config.login?.type === "iam") {
    throw "This account is not configured for SSH access via the P0 CLI";
  }

  return config.login?.type === "idc"
    ? await assumeRoleWithIdc(data as AwsSshIdcRequest)
    : config.login?.type === "federated"
      ? await assumeRoleWithOktaSaml(authn, data as AwsSshRoleRequest)
      : throwAssertNever(config.login);
};

export const sshOrScp = async (
  authn: Authn,
  data: SshRequest,
  cmdArgs: ScpCommandArgs | SshCommandArgs,
  privateKey: string
) => {
  if (!privateKey) {
    throw "Failed to load a private key for this request. Please contact support@p0.dev for assistance.";
  }

  // TODO ENG-2284 support login with Google Cloud
  const credential: AwsCredentials | undefined =
    data.type === "aws" ? await awsLogin(authn, data) : undefined;

  return withSshAgent(cmdArgs, async () => {
    const { command, args } = createProxyCommands(data, cmdArgs, cmdArgs.debug);

    if (cmdArgs.debug) {
      const reproCommands = [
        `eval $(ssh-agent)`,
        `ssh-add "${PRIVATE_KEY_PATH}"`,
        // TODO ENG-2284 support login with Google Cloud
        // TODO: Modify commands to add the ability to get permission set commands
        ...(data.type === "aws" && data.subType !== "idc"
          ? [
              `eval $(p0 aws role assume ${data.role} --account ${data.accountId})`,
            ]
          : []),
        `${command} ${transformForShell(args).join(" ")}`,
      ];
      print2(
        `Execute the following commands to create a similar SSH/SCP session:\n*** COMMANDS BEGIN ***\n${reproCommands.join("\n")}\n*** COMMANDS END ***"\n`
      );
    }

    const maxRetries =
      data.type === "gcloud" ? GCP_MAX_SSH_RETRIES : DEFAULT_MAX_SSH_RETRIES;

    return spawnSshNode({
      credential,
      abortController: new AbortController(),
      command,
      args,
      stdio: ["inherit", "inherit", "pipe"],
      debug: cmdArgs.debug,
      provider: data.type,
      attemptsRemaining: maxRetries,
    });
  });
};
