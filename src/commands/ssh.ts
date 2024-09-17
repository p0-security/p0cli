/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authenticate } from "../drivers/auth";
import { guard } from "../drivers/firestore";
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
        .option("L", {
          type: "string",
          // Copied from `man ssh`
          describe:
            "Specifies that connections to the given TCP port or Unix socket on the local (client) host are to be forwarded to the given host and port, or Unix socket, on the remote side.",
        })
        .option("R", {
          type: "string",
          // Copied from `man ssh`
          describe:
            "Specifies that connections to the given TCP port or Unix socket on the remote (server) host are to be forwarded to the local side.",
        })
        .option("N", {
          type: "boolean",
          describe:
            "Do not execute a remote command. Useful for forwarding ports.",
        })
        .option("A", {
          type: "boolean",
          describe:
            "Enables forwarding of connections from an authentication agent such as ssh-agent",
        })
        .option("o", {
          type: "string",
          describe:
            "Can be used to give options in the format used in the SSH configuration file.",
        })
        // Match `p0 request --reason`
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
          choices: ["aws", "gcloud"],
        })
        .option("debug", {
          type: "boolean",
          describe: "Print debug information.",
        }),
    guard(sshAction)
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
