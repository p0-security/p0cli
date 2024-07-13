/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { ScpCommandArgs, SshCommandArgs } from "../../../commands/shared";
import { PRIVATE_KEY_PATH } from "../../../common/keys";
import { print2 } from "../../../drivers/stdio";
import { Authn } from "../../../types/identity";
import { assumeRoleWithOktaSaml } from "../../okta/aws";
import { withSshAgent } from "../../ssh-agent";
import { AwsCredentials, AwsSsh, GcpSsh, ProviderSsh } from "../types";
import { ensureSsmInstall } from "./install";
import {
  ChildProcessByStdio,
  StdioNull,
  StdioPipe,
  spawn,
} from "node:child_process";
import { Readable } from "node:stream";

const UNPROVISIONED_GCLOUD_ACCESS_MESSAGE = /TODO/;
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
const START_SSH_SESSION_DOCUMENT_NAME = "AWS-StartSSHSession";

type SsmArgs = {
  instance: string;
  region: string;
  requestId: string;
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
  child: ChildProcessByStdio<null, null, Readable>
) => {
  let isEphemeralAccessDeniedException = false;
  const beforeStart = Date.now();

  child.stderr.on("data", (chunk) => {
    const chunkString = chunk.toString("utf-8");
    const match =
      chunkString.match(UNPROVISIONED_ACCESS_MESSAGE) ||
      chunkString.match(UNPROVISIONED_SCP_ACCESS_MESSAGE) ||
      chunkString.match(UNPROVISIONED_GCLOUD_ACCESS_MESSAGE);

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

const spawnChildProcess = (
  credential: AwsCredentials | GcpCredentials,
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

type GcpCredentials = {
  todo: string;
};

type SpawnSsmNodeOptions = {
  credential: AwsCredentials | GcpCredentials;
  provider: "aws" | "gcloud";
  command: string;
  args: string[];
  attemptsRemaining?: number;
  abortController?: AbortController;
  detached?: boolean;
  stdio: [StdioNull, StdioNull, StdioPipe];
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
      options.stdio
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
            `Access did not propagate through ${options.provider} before max retry attempts were exceeded. Please contact support@p0.dev for assistance.`
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

const createProxyCommands = (
  args: ScpCommandArgs | SshCommandArgs,
  opts: {
    linuxUserName: string;
    instanceId: string;
    region: string;
    debug?: boolean;
  }
) => {
  const { region, debug, linuxUserName, instanceId } = opts;
  const ssmCommand = [
    ...createBaseSsmCommand({
      region,
      instance: "%h",
    }),
    "--document-name",
    START_SSH_SESSION_DOCUMENT_NAME,
    "--parameters",
    '"portNumber=%p"',
  ];

  const commonArgs = [
    ...(debug ? ["-v"] : []),
    "-o",
    `ProxyCommand=${ssmCommand.join(" ")}`,
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
      `${linuxUserName}@${instanceId}`,
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

export const sshOrScp = async (
  authn: Authn,
  data: ProviderSsh,
  cmdArgs: ScpCommandArgs | SshCommandArgs,
  privateKey: string
) => {
  if (!(await ensureSsmInstall())) {
    throw "Please try again after installing the required AWS utilities";
  }

  if (!privateKey) {
    throw "Failed to load a private key for this request. Please contact support@p0.dev for assistance.";
  }

  if (data.permission.spec.type === "aws") {
    return awsSpecificLogic(authn, data as AwsSsh, cmdArgs);
  } else {
    return gcpSpecificLogic(authn, data as GcpSsh, cmdArgs);
  }
};

const awsSpecificLogic = async (
  authn: Authn,
  data: AwsSsh,
  cmdArgs: ScpCommandArgs | SshCommandArgs
) => {
  const { instanceId, accountId, region } = data.permission.spec;
  const { name, ssh } = data.generated;
  const credential = await assumeRoleWithOktaSaml(authn, {
    account: accountId,
    role: name,
  });

  return withSshAgent(cmdArgs, async () => {
    const { command, args } = createProxyCommands(cmdArgs, {
      linuxUserName: ssh.linuxUserName,
      region,
      instanceId,
      debug: cmdArgs.debug, // TODO: do we need to pass this separately?
    });

    if (cmdArgs.debug) {
      const reproCommands = [
        `eval $(ssh-agent)`,
        `ssh-add "${PRIVATE_KEY_PATH}"`,
        `eval $(p0 aws role assume ${name} --account ${accountId})`,
        `${command} ${transformForShell(args).join(" ")}`,
      ];
      print2(
        `Execute the following commands to create a similar SSH/SCP session:\n*** COMMANDS BEGIN ***\n${reproCommands.join("\n")}\n*** COMMANDS END ***"\n`
      );
    }

    return spawnSsmNode({
      provider: "aws",
      credential,
      abortController: new AbortController(), // TODO: we probably don't need abort controller at all anymore
      command,
      args,
      stdio: ["inherit", "inherit", "pipe"],
    });
  });
};

const gcpSpecificLogic = async (
  authn: Authn,
  data: GcpSsh,
  cmdArgs: ScpCommandArgs | SshCommandArgs
) => {
  // TODO: how do we assume the role with Okta SAML for GCP?
  const credential = await assumeRoleWithOktaSaml(authn, {
    role: "TODO: gcloud specific?",
    account: "TODO: gcloud specific?",
  });

  const { command, args } = createGcloudProxyCommands(
    cmdArgs,
    data.permission.spec
  );

  return spawnSsmNode({
    credential,
    provider: "gcloud",
    abortController: new AbortController(), // TODO: we probably don't need abort controller at all anymore
    command,
    args,
    stdio: ["inherit", "inherit", "pipe"],
  });
};

const createGcloudProxyCommands = (
  cmdArgs: ScpCommandArgs | SshCommandArgs,
  { projectId, zone, instanceName }: GcpSsh["permission"]["spec"]
) => {
  return {
    command: "gcloud",
    args: [
      "compute",
      "ssh",
      "--project",
      projectId,
      "--zone",
      zone,
      instanceName,
    ],
  };
};
