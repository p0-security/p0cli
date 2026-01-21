/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authenticate } from "../drivers/auth";
import { print2 } from "../drivers/stdio";
import { exitProcess } from "../opentelemetry/otel-helpers";
import { rdp } from "../plugins/rdp";
import { RdpCommandArgs } from "../types/rdp";
import { getAppName, getOperatingSystem } from "../util";
import yargs from "yargs";

export const rdpCommand = (yargs: yargs.Argv) =>
  yargs.command<RdpCommandArgs>(
    "rdp <destination>",
    "Connect to a Windows virtual machine via RDP",
    (yargs) =>
      yargs
        .positional("destination", {
          type: "string",
          demandOption: true,
        })
        .option("reason", {
          describe: "Reason access is needed",
          type: "string",
        })
        .option("debug", {
          type: "boolean",
          describe: "Print debug information.",
          default: false,
        })
        .option("configure", {
          type: "boolean",
          describe: "Configure the RDP session before connecting",
          default: false,
        })
        .usage("$0 rdp <destination>")
        .epilogue(
          `Connect to a Windows virtual machine via RDP through Azure Bastion Host.

Example:
  $ ${getAppName()} rdp my-windows-vm --reason "Reason for access"`
        ),

    rdpAction
  );

/**
 * Connect to a Virtual Machine via RDP
 *
 * Implicitly requests access to the machine if not already granted.
 * Implicitly logs the user into Azure if not already logged in.
 *
 * Supported RDP mechanisms:
 * - Azure VM via Bastion Host with Entra ID authentication
 */
const rdpAction = async (cmdArgs: yargs.ArgumentsCamelCase<RdpCommandArgs>) => {
  // Entra ID authentication is only supported on Windows client machines.
  // See: https://learn.microsoft.com/en-us/windows/client-management/client-tools/connect-to-remote-aadj-pc#connect-with-microsoft-entra-authentication
  const os = getOperatingSystem();
  if (os !== "win") {
    print2("RDP session connections are only supported on Windows.");
    exitProcess(1);
  }

  const authn = await authenticate(cmdArgs);
  await rdp(authn, cmdArgs);

  // Force exit to prevent hanging due to orphaned child processes
  // Skip in tests to avoid killing the test runner
  if (process.env.NODE_ENV !== "unit") {
    exitProcess(0);
  }
};
