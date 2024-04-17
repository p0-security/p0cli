/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { guard } from "../drivers/firestore";
import { print2 } from "../drivers/stdio";
import { sshRequest } from "../plugins/aws/ssm/request";
import { detectPathType, ssmScpLocalToRemote } from "../plugins/aws/ssm/scp";
import { ScpCommandArgs } from "./types";
import yargs from "yargs";

const PORT_PATTERN = /^\d+$/;

export const scpCommand = (yargs: yargs.Argv) =>
  yargs.command<ScpCommandArgs>(
    "scp <source> <destination>",
    'Securely copy files to remote machine. The source and destination may be specified as a local pathname, a remote host with optional path in the form host:[path], or a URI in the form scp://host[:port][/path]. Local file names can be made explicit using absolute or relative pathnames to avoid scp treating file names containing ":" as host specifiers.',
    (yargs) =>
      yargs
        .positional("source", {
          type: "string",
          demandOption: true,
        })
        .positional("destination", {
          type: "string",
          demandOption: true,
        })
        .check((argv: yargs.ArgumentsCamelCase<ScpCommandArgs>) => {
          if (argv.port == null) return true;
          return argv.port.match(PORT_PATTERN) || "Port must be a number";
        })
        .option("port", {
          type: "string",
          alias: "P",
          describe:
            "The port to set up port-forwarding. It is used both on the local and remote machine.",
        })
        .option("sudo", {
          type: "boolean",
          describe: "Add user to sudoers file",
        })
        .option("reason", {
          describe: "Reason access is needed",
          type: "string",
        })
        .option("account", {
          type: "string",
          describe: "The account on which the instance is located",
        }),
    guard(scp)
  );

const scp = async (args: yargs.ArgumentsCamelCase<ScpCommandArgs>) => {
  const source = args.source;
  const destination = args.destination;
  const sourcePath = detectPathType(source);
  const destinationPath = detectPathType(destination);

  // TODO support remote to local
  if (sourcePath.type !== "local" || destinationPath.type !== "remote") {
    print2(
      `Source must be local and destination must be remote. Got: source is ${sourcePath.type} and destination is ${destinationPath.type}.`
    );
    return;
  }

  const baseArgs = { ...args, destination: destinationPath.host };

  const response = await sshRequest(baseArgs);
  if (!response) return;

  const { authn, requestWithId } = response;

  await ssmScpLocalToRemote(
    authn,
    requestWithId,
    args,
    sourcePath,
    destinationPath
  );
};
