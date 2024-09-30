/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { SshProvider } from "../../types/ssh";
import {
  AzureSshLocalData,
  AzureSshPermissionSpec,
  AzureSshRequest,
} from "./types";
import { hierarchyInfo } from "./util";

/** Maximum number of attempts to start an SSH session
 *
 * The length of each attempt varies based on the type of error from a few seconds to < 1s
 */
const MAX_SSH_RETRIES = 120;

export const azureSshProvider: SshProvider<
  AzureSshPermissionSpec,
  AzureSshLocalData,
  AzureSshRequest
> = {
  requestToSsh: (request) => {
    return {
      // TODO: Azure doesn't use linuxUserName, derived from the user's identity
      // `miguel.campos@p0.dev@azure-node-1:~$`
      linuxUserName: "",
      id: request.permission.spec.instanceId,
      bastionHostId: request.permission.spec.bastionHostId,
      type: "azure",
    };
  },
  toCliRequest: async (request, _options) => ({
    ...request,
    cliLocalData: undefined,
  }),
  ensureInstall: async () => {
    // TODO: Support Azure Login
  },
  cloudProviderLogin: async () => undefined, // TODO: Support Azure Login
  reproCommands: () => undefined, // TODO: Support Azure Login
  proxyCommand: ({ bastionHostId, id }) => {
    // az network bastion ssh --name bastions-1 --resource-group bastions-group --target-resource-id /subscriptions/ad1e5b28-ccb7-4bfd-9955-ec0e16b8ae66/resourceGroups/VM-GROUP/providers/Microsoft.Compute/virtualMachines/azure-node-1 --auth-type AAD
    const bastion = hierarchyInfo(bastionHostId);
    if (!bastion || !bastion.resourceId || !bastion.resourceGroupId) {
      throw new Error("Selected bastion is invalid");
    }

    return [
      "network",
      "bastion",
      "ssh",
      "--name",
      bastion.resourceId,
      "--resource-group",
      bastion.resourceGroupId,
      "--target-resource-id",
      id,
      "--auth-type",
      "AAD",
    ];
  },
  preTestAccessPropagationArgs: () => undefined, // TODO: Determine if Azure requires any special arguments
  maxRetries: MAX_SSH_RETRIES,
  friendlyName: "Azure",
};
