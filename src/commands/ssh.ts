/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authenticate } from "../drivers/auth";
import { fsShutdownGuard } from "../drivers/firestore";
import { sshOrScp } from "../plugins/ssh";
import { SshCommandArgs, prepareRequest } from "./shared/ssh";
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
          choices: ["aws", "gcloud"],
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
  Flags and positionals passed to the underlying ssh implementation.
  The '--' argument must be specified between P0-specific args on the left and SSH_ARGS on the right. Example;

  $ p0 ssh example-instance --provider gcloud -- -NR '*:8080:localhost:8088' -o 'GatewayPorts yes'`
        ),

    fsShutdownGuard(sshAction)
  );

/** Connect to an SSH backend
 *
 * Implicitly gains access to the SSH resource if required.
 *
 * Supported SSH mechanisms:
 * - AWS EC2 via SSM with Okta SAML
 */
const sshAction = async (args: yargs.ArgumentsCamelCase<SshCommandArgs>) => {
  // Prefix is required because the backend uses it to determine that this is an AWS request
  const authn = await authenticate();

  const sshOptions: string[] = Array.isArray(args["--"])
    ? args["--"].map(String)
    : [];
  args.sshOptions = sshOptions;

  const { request, privateKey, sshProvider } = await prepareRequest(
    authn,
    args,
    args.destination
  );

  await sshOrScp({
    authn,
    request,
    cmdArgs: args,
    privateKey,
    sshProvider,
  });
};
