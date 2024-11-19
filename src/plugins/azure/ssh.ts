/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { SshProvider } from "../../types/ssh";
import { getAzPrincipal } from "./auth";
import { ensureAzInstall } from "./install";
import {
  AD_CERT_FILENAME,
  AD_SSH_KEY_PRIVATE,
  createTempDirectoryForKeys,
  generateSshKeyAndAzureAdCert,
} from "./keygen";
import { trySpawnBastionTunnel } from "./tunnel";
import {
  AzureLocalData,
  AzureSshPermissionSpec,
  AzureSshRequest,
} from "./types";
import path from "node:path";

// TODO: Determine what this value should be for Azure
const PROPAGATION_TIMEOUT_LIMIT_MS = 2 * 60 * 1000;

export const azureSshProvider: SshProvider<
  AzureSshPermissionSpec,
  AzureLocalData,
  AzureSshRequest
> = {
  // TODO: Natively support Azure login in P0 CLI
  cloudProviderLogin: async () => {
    // Login is handled as part of setup() below
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

  // TODO: Determine if necessary
  preTestAccessPropagationArgs: () => undefined,

  // Azure doesn't support ProxyCommand, as nice as that would be. Yet.
  proxyCommand: () => [],

  // TODO: Determine if necessary
  reproCommands: () => undefined,

  setup: async (request) => {
    await generateSshKeyAndAzureAdCert(request.sshKeyPath);

    const { killTunnel, tunnelLocalPort } =
      await trySpawnBastionTunnel(request);

    // Ensure the tunnel is killed when the CLI exits
    process.on("exit", () => killTunnel());

    request.killTunnel = killTunnel;

    const sshPrivateKeyPath = path.join(request.sshKeyPath, AD_SSH_KEY_PRIVATE);
    const sshCertificateKeyPath = path.join(
      request.sshKeyPath,
      AD_CERT_FILENAME
    );

    return {
      sshOptions: [
        "UserKnownHostsFile /dev/null",
        `IdentityFile ${sshPrivateKeyPath}`,
        `CertificateFile ${sshCertificateKeyPath}`,
        "IdentitiesOnly yes",
        // Entra ID usernames are email addresses, so to not break scp we need to pass in the username as an option
        // like so
        `User ${request.linuxUserName}`,
      ],
      tunnelLocalPort,
    };
  },

  teardown: async (request) => {
    if (request.killTunnel) {
      request.killTunnel();
    }

    await request.sshKeyPathCleanup();
  },

  requestToSsh: (request) => ({
    type: "azure",
    id: "localhost",
    ...request.cliLocalData,
    instanceId: request.permission.resource.instanceId,
    subscriptionId: request.permission.resource.subscriptionId,
    instanceResourceGroup: request.permission.resource.resourceGroupId,
    bastionName: request.permission.resource.bastionName,
    bastionResourceGroup: request.permission.resource.bastionResourceGroup,
  }),

  // TODO: Implement
  unprovisionedAccessPatterns: [],

  toCliRequest: async (request) => {
    const { path, cleanup } = await createTempDirectoryForKeys();

    return {
      ...request,
      cliLocalData: {
        linuxUserName: await getAzPrincipal(),
        sshKeyPath: path,
        sshKeyPathCleanup: cleanup,
      },
    };
  },
};
