/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { SshProvider } from "../../types/ssh";
import { exec } from "../../util";
import { importSshKey } from "../google/ssh-key";
import { ensureAzInstall } from "./install";
import { AzureSshPermissionSpec, AzureSshRequest } from "./types";

// TODO: Determine what this value should be for Azure
const PROPAGATION_TIMEOUT_LIMIT_MS = 2 * 60 * 1000;

export const azureSshProvider: SshProvider<
  AzureSshPermissionSpec,
  { linuxUserName: string },
  AzureSshRequest
> = {
  // TODO: Natively support Azure login in P0 CLI
  cloudProviderLogin: async () => {
    // Always invoke `az login` before each SSH access. This is needed because
    // Azure permissions are only updated upon login.
    await exec("az", ["login"]);
    return undefined;
  },

  ensureInstall: async () => {
    if (!(await ensureAzInstall())) {
      throw "Please try again after installing the Azure CLI tool.";
    }
  },

  friendlyName: "Microsoft Azure",

  loginRequiredMessage: "Please log in to Azure with 'az login' to continue.",

  // TODO: Determine value
  loginRequiredPattern: undefined,

  propagationTimeoutMs: PROPAGATION_TIMEOUT_LIMIT_MS,

  // TODO: Implement
  preTestAccessPropagationArgs: () => undefined,

  // TODO: Determine if necessary
  proxyCommand: () => [],

  // TODO: Determine if necessary
  reproCommands: () => undefined,

  // TODO: Placeholder
  requestToSsh: (request) => ({
    type: "azure",
    id: request.permission.spec.instanceId,
    instanceId: request.permission.spec.instanceId,
    linuxUserName: request.cliLocalData.linuxUserName,
  }),

  // TODO: Implement
  unprovisionedAccessPatterns: [],

  // TODO: Placeholder
  toCliRequest: async (request, options) => ({
    ...request,
    cliLocalData: {
      linuxUserName: await importSshKey(
        request.permission.spec.publicKey,
        options
      ),
    },
  }),
};
