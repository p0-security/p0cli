/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { AzureRdpRequest } from "../../types/rdp";
import { PermissionRequest } from "../../types/request";
import { exec, osSafeCommand } from "../../util";
import { azSetSubscription } from "./auth";

const azBastionRdpCommand = (
  request: PermissionRequest<AzureRdpRequest>,
  options: { configure?: boolean; debug?: boolean }
) => {
  const { configure, debug } = options;
  const { bastionName, bastionRg, instanceId } = request.permission.resource;
  return osSafeCommand("az", [
    "network",
    "bastion",
    "rdp",
    "--name",
    bastionName,
    "--resource-group",
    bastionRg,
    "--target-resource-id",
    instanceId,
    "--auth-type",
    "aad",
    ...(configure ? ["--configure"] : []),
    ...(debug ? ["--debug"] : []),
  ]);
};

export const azureRdpProvider = {
  setup: async (
    request: PermissionRequest<AzureRdpRequest>,
    options: { debug?: boolean }
  ) => {
    const entraIdUserEmail = await azSetSubscription(
      request.permission.resource,
      options
    );
    return { entraIdUserEmail };
  },

  spawnConnection: async (
    request: PermissionRequest<AzureRdpRequest>,
    options: {
      configure?: boolean;
      debug?: boolean;
    }
  ) => {
    const { debug } = options;

    if (debug) {
      print2("Creating Azure Bastion RDP connection...");
    }

    try {
      const { command, args } = azBastionRdpCommand(request, options);

      if (debug) {
        print2(`Executing: ${command} ${args.join(" ")}`);
      }

      await exec(command, args, { check: true });
    } catch (error: any) {
      if (debug) {
        print2(`Azure Bastion RDP command failed: ${error.message}`);
        if (error.stderr) {
          print2("Error details:");
          print2(error.stderr);
        }
      }
      throw new Error(
        `Failed to create Azure Bastion RDP connection: ${error.message}`
      );
    }
  },
};
