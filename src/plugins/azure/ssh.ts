/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { SshProvider } from "../../types/ssh";
import { azLogin } from "./auth";
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

  // TODO(ENG-3149): Implement sudo access checks here
  preTestAccessPropagationArgs: () => undefined,

  // Azure doesn't support ProxyCommand, as nice as that would be. Yet.
  proxyCommand: () => [],

  // TODO: Determine if necessary
  reproCommands: () => undefined,

  setup: async (request) => {
    // TODO(ENG-3129): Does this specifically need to be the subscription ID for the Bastion?
    await azLogin(request.subscriptionId); // Always re-login to Azure CLI

    const { path: keyPath, cleanup: sshKeyPathCleanup } =
      await createTempDirectoryForKeys();

    const wrappedCreateCertAndTunnel = async () => {
      try {
        await generateSshKeyAndAzureAdCert(keyPath);
        return await trySpawnBastionTunnel(request);
      } catch (error: any) {
        await sshKeyPathCleanup();
        throw error;
      }
    };

    const { killTunnel, tunnelLocalPort } = await wrappedCreateCertAndTunnel();

    const sshPrivateKeyPath = path.join(keyPath, AD_SSH_KEY_PRIVATE);
    const sshCertificateKeyPath = path.join(keyPath, AD_CERT_FILENAME);

    const teardown = async () => {
      await killTunnel();
      await sshKeyPathCleanup();
    };

    return {
      sshOptions: [
        `IdentityFile ${sshPrivateKeyPath}`,
        `CertificateFile ${sshCertificateKeyPath}`,
        "IdentitiesOnly yes",

        // Because we connect to the Azure Network Bastion tunnel via a local port instead of a ProxyCommand, every
        // instance connected to will appear to `ssh` to be the same host but presenting a different host key (i.e.,
        // `ssh` always connects to localhost but each VM will present its own host key), which will trigger MITM attack
        // warnings. We disable host key checking to avoid this. This is ordinarily very dangerous, but in this case,
        // security of the connection is ensured by the Azure Bastion Network tunnel, which utilizes HTTPS and thus has
        // its own MITM protection.
        "StrictHostKeyChecking no",
        "UserKnownHostsFile /dev/null",
      ],
      port: tunnelLocalPort,
      teardown,
    };
  },

  requestToSsh: (request) => ({
    type: "azure",
    id: "localhost",
    ...request.cliLocalData,
    instanceId: request.permission.resource.instanceId,
    subscriptionId: request.permission.resource.subscriptionId,
    instanceResourceGroup: request.permission.resource.resourceGroupId,
    bastionId: request.permission.bastionHostId,
  }),

  // TODO: Implement
  unprovisionedAccessPatterns: [],

  toCliRequest: async (request) => {
    return {
      ...request,
      cliLocalData: {
        linuxUserName: request.principal,
      },
    };
  },
};
