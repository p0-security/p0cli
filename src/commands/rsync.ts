/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authenticate } from "../drivers/auth";
import { sshOrScp } from "../plugins/ssh";
import { SshRequest, SupportedSshProviders } from "../types/ssh";
import { prepareRequest, RsyncCommandArgs } from "./shared/ssh";
import { cleanupStaleSshConfigs } from "./shared/ssh-cleanup";
import yargs from "yargs";

export const rsyncCommand = (yargs: yargs.Argv) =>
  yargs.command<RsyncCommandArgs>(
    "rsync <source> <destination>",
    "Rsync copies files between a local and remote host with better performance for large transfers.",
    (yargs) =>
      yargs
        .positional("source", {
          type: "string",
          demandOption: true,
          description: "Format [hostname:]file",
        })
        .positional("destination", {
          type: "string",
          demandOption: true,
          description: "Format [hostname:]file",
        })
        .option("reason", {
          describe: "Reason access is needed",
          type: "string",
        })
        .option("account", {
          type: "string",
          describe: "The account on which the instance is located",
        })
        .option("provider", {
          type: "string",
          describe: "The cloud provider where the instance is hosted",
          choices: SupportedSshProviders,
        })
        .option("sudo", {
          type: "boolean",
          describe: "Add user to sudoers file",
        })
        .option("debug", {
          type: "boolean",
          describe: "Print debug information.",
        })
        .usage("rsync <source> <destination> [-- RSYNC_ARGS ...]")
        // Enable populate-- to capture rsync-specific options after `--`
        .parserConfiguration({
          "populate--": true,
        })
        .epilogue(
          `[-- RSYNC_ARGS ...]
  Flags and positionals passed to the underlying rsync implementation.
  The '--' argument must be specified between P0-specific args on the left and RSYNC_ARGS on the right.`
        ),

    rsyncAction
  );

/** Transfers files between a local and remote hosts using SSH via rsync.
 *
 * Implicitly gains access to the SSH resource if required.
 */
const rsyncAction = async (args: yargs.ArgumentsCamelCase<RsyncCommandArgs>) => {
  // Clean up any stale SSH config files before proceeding
  await cleanupStaleSshConfigs(args.debug);

  const authn = await authenticate(args);

  const sshOptions: string[] = Array.isArray(args["--"])
    ? args["--"].map(String)
    : [];
  args.sshOptions = sshOptions;

  // TODO(ENG-3142): Azure SSH currently doesn't support specifying a port; throw an error if one is set.
  if (
    args.provider === "azure" &&
    sshOptions.some((opt) => opt.startsWith("-P") || opt.startsWith("-p"))
  ) {
    throw "Azure SSH does not currently support specifying a port. SSH on the target VM must be listening on the default port 22.";
  }

  const host = getHostIdentifier(args.source, args.destination);

  if (!host) {
    throw "Could not determine host identifier from source or destination";
  }

  const { request, requestId, privateKey, sshProvider, sshHostKeys } =
    await prepareRequest(authn, args, host);

  // replace the host with the linuxUserName@instanceId
  const { source, destination } = replaceHostWithInstance(request, args);

  const exitCode = await sshOrScp({
    authn,
    request,
    requestId,
    cmdArgs: {
      ...args,
      source,
      destination,
      _commandType: "rsync" as const,
    },
    privateKey,
    sshProvider,
    sshHostKeys,
  });

  // Force exit to prevent hanging due to orphaned child processes (e.g., session-manager-plugin)
  // holding open file descriptors. See: https://github.com/aws/amazon-ssm-agent/issues/173
  // Skip in tests to avoid killing the test runner
  if (process.env.NODE_ENV !== "unit") {
    process.exit(exitCode ?? 0);
  }
};

/** If a path is not explicitly local, use this pattern to determine if it's remote */
const REMOTE_PATTERN_COLON = /^([^:]+:)(.*)$/; // Matches host:[path]

// TODO (ENG-1931): Improve remote host and local host checking for SCP requests
const isExplicitlyRemote = (path: string): boolean => {
  return REMOTE_PATTERN_COLON.test(path);
};

const getHostIdentifier = (source: string, destination: string) => {
  // the instance is contained in the source or destination and is always delimited by a colon.
  const isSourceRemote = isExplicitlyRemote(source);
  const isDestinationRemote = isExplicitlyRemote(destination);

  const remote = isSourceRemote ? source : destination;

  if (isSourceRemote != isDestinationRemote) {
    return remote.split(":")[0];
  }

  // TODO (ENG-1930): support scp across multiple remote hosts.
  throw "Exactly one host (source or destination) must be remote.";
};

const replaceHostWithInstance = (result: SshRequest, args: RsyncCommandArgs) => {
  let source = args.source;
  let destination = args.destination;

  if (isExplicitlyRemote(source)) {
    source = `${result.linuxUserName}@${result.id}:${source.split(":")[1]}`;
  }

  if (isExplicitlyRemote(destination)) {
    destination = `${result.linuxUserName}@${result.id}:${destination.split(":")[1]}`;
  }

  return { source, destination };
};

