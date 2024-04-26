/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchExerciseGrant } from "../drivers/api";
import { authenticate } from "../drivers/auth";
import { guard } from "../drivers/firestore";
import { ssm } from "../plugins/aws/ssm";
import { SshCommandArgs, provisionRequest } from "./shared";
import yargs from "yargs";

// Matches strings with the pattern "digits:digits" (e.g. 1234:5678)
const LOCAL_PORT_FORWARD_PATTERN = /^\d+:\d+$/;

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
        .option("sudo", {
          type: "boolean",
          describe: "Add user to sudoers file",
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
        .check((argv: yargs.ArgumentsCamelCase<SshCommandArgs>) => {
          if (argv.L == null) return true;

          return (
            argv.L.match(LOCAL_PORT_FORWARD_PATTERN) ||
            "Local port forward should be in the format `local_port:remote_port`"
          );
        })
        .option("L", {
          type: "string",
          describe:
            // the order of the sockets in the address matches the ssh man page
            "Forward a local port to the remote host; `local_socket:remote_socket`",
        })
        .option("N", {
          type: "boolean",
          describe:
            "Do not execute a remote command. Useful for forwarding ports.",
        })
        // Match `p0 request --reason`
        .option("reason", {
          describe: "Reason access is needed",
          type: "string",
        })
        .option("account", {
          type: "string",
          describe: "The account on which the instance is located",
        }),
    guard(ssh)
  );

/** Connect to an SSH backend
 *
 * Implicitly gains access to the SSH resource if required.
 *
 * Supported SSH mechanisms:
 * - AWS EC2 via SSM with Okta SAML
 */
const ssh = async (args: yargs.ArgumentsCamelCase<SshCommandArgs>) => {
  // Prefix is required because the backend uses it to determine that this is an AWS request
  const authn = await authenticate();

  const destination = args.destination;

  const requestId = await provisionRequest(authn, args, destination);
  if (!requestId) {
    throw "Server did not return a request id. Please contact support@p0.dev for assistance.";
  }

  const result = await fetchExerciseGrant(authn, {
    requestId,
    destination,
  });

  await ssm(authn, result, args);
};
