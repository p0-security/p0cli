/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authenticate } from "../drivers/auth";
import { traceSpan } from "../opentelemetry/otel-helpers";
import { sshOrScp } from "../plugins/ssh";
import { getAppName } from "../util";
import { prepareRequest, SshCommandArgs } from "./shared/ssh";
import { cleanupStaleSshConfigs } from "./shared/ssh-cleanup";
import yargs from "yargs";

export const sshCommand = (yargs: yargs.Argv) =>
  yargs.command<SshCommandArgs>(
    "ssh <destination> [command [arguments..]]",
    "SSH into a virtual machine",
    (yargs) =>
      yargs
        .positional("destination", {
          type: "string",
          demandOption: true,
        })
        .positional("command", {
          type: "string",
          describe: "Pass command to the shell",
        })
        .positional("arguments", {
          describe: "Command arguments",
          array: true,
          string: true,
          default: [] as string[],
        })
        .option("sudo", {
          type: "boolean",
          describe: "Add user to sudoers file",
        })
        // Match `p0 request --reason`
        .option("reason", {
          describe: "Reason access is needed",
          type: "string",
        })
        .option("parent", {
          type: "string",
          describe:
            "The containing parent resource which the instance belongs to (account, project, subscription, etc.)",
        })
        .option("provider", {
          type: "string",
          describe: "The cloud provider where the instance is hosted",
          choices: ["aws", "azure", "gcloud", "self-hosted"],
        })
        .option("debug", {
          type: "boolean",
          describe: "Print debug information.",
        })
        .usage("$0 ssh <destination> [command [arguments..]] [-- SSH_ARGS ...]")
        // Enable populate-- to capture SSH-specific options after `--`
        .parserConfiguration({
          "populate--": true,
        })
        .epilogue(
          `[-- SSH_ARGS ...]
  Options passed to the underlying ssh implementation.
  The '--' argument must be specified between P0-specific args on the left and SSH_ARGS on the right. Example;

  $ ${getAppName()} ssh example-instance --provider gcloud -- -NR '*:8080:localhost:8088' -o 'GatewayPorts yes'`
        ),

    sshAction
  );

/** Connect to an SSH backend
 *
 * Implicitly gains access to the SSH resource if required.
 *
 * Supported SSH mechanisms:
 * - AWS EC2 via SSM with Okta SAML
 */
const sshAction = async (args: yargs.ArgumentsCamelCase<SshCommandArgs>) => {
  await traceSpan(
    "ssh.command",
    async (span) => {
      span.setAttribute("destination", args.destination);
      if (args.provider) {
        span.setAttribute("provider", args.provider);
      }
      if (args.sudo) {
        span.setAttribute("sudo", args.sudo);
      }

      // Clean up any stale SSH config files before proceeding
      await cleanupStaleSshConfigs(args.debug);

      // Prefix is required because the backend uses it to determine that this is an AWS request
      const authn = await authenticate(args);

      const sshOptions: string[] = Array.isArray(args["--"])
        ? args["--"].map(String)
        : [];
      args.sshOptions = sshOptions;

      // TODO(ENG-3142): Azure SSH currently doesn't support specifying a port; throw an error if one is set.
      if (
        args.provider === "azure" &&
        sshOptions.some((opt) => opt.startsWith("-p"))
      ) {
        throw "Azure SSH does not currently support specifying a port. SSH on the target VM must be listening on the default port 22.";
      }

      const { request, requestId, privateKey, sshProvider, sshHostKeys } =
        await prepareRequest(authn, args, args.destination);

      const exitCode = await sshOrScp({
        authn,
        request,
        requestId,
        cmdArgs: args,
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
    },
    {
      command: "ssh",
    }
  );
};
