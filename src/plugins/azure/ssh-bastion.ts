/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { SshProvider } from "../../types/ssh";
import { getOperatingSystem } from "../../util";
import { createTempDirectoryForKeys } from "../ssh/shared";
import { azSetSubscription } from "./auth";
import {
  AD_CERT_FILENAME,
  AD_SSH_KEY_PRIVATE,
  azureSshLoginReproCommands,
  azureSshProviderBase,
  generateSshKeyAndAzureAdCert,
} from "./ssh-shared";
import { azBastionTunnelCommand, trySpawnBastionTunnel } from "./tunnel";
import {
  AzureLocalData,
  AzureSshPermissionSpec,
  AzureSshRequest,
} from "./types";
import path from "node:path";

export const azureSshProvider: SshProvider<
  AzureSshPermissionSpec,
  AzureLocalData,
  AzureSshRequest
> = {
  ...azureSshProviderBase,

  proxyCommand: (_, port) => {
    const targetPort = port ?? "22";
    // On Windows, use ncat (from nmap). On Unix/Mac, use nc.
    // Both have the same command line syntax: command localhost port
    const command = getOperatingSystem() === "win" ? "ncat" : "nc";
    return [command, "localhost", targetPort];
  },

  reproCommands: (request, additionalData) => {
    // If additionalData is undefined (which should be never for the azureSshProvider), use the default port for Azure
    // Network Bastion tunnels instead of generating a random one
    const { command: azTunnelExe, args: azTunnelArgs } = azBastionTunnelCommand(
      request,
      additionalData?.port ?? "50022"
    );

    return [
      ...azureSshLoginReproCommands(request, additionalData),
      `${azTunnelExe} ${azTunnelArgs.join(" ")}`,
    ];
  },

  generateKeys: async (_authn, request, options) => {
    const { debug } = options;
    const { path: keyPath } = await createTempDirectoryForKeys();
    await azSetSubscription(request, options);
    await generateSshKeyAndAzureAdCert(keyPath, { debug });
    const sshPrivateKeyPath = path.join(keyPath, AD_SSH_KEY_PRIVATE);
    const sshCertificateKeyPath = path.join(keyPath, AD_CERT_FILENAME);

    return {
      privateKeyPath: sshPrivateKeyPath,
      certificatePath: sshCertificateKeyPath,
    };
  },

  setupProxy: async (request, options) => {
    const { killTunnel, tunnelLocalPort } = await trySpawnBastionTunnel(
      request,
      options
    );

    return {
      teardown: killTunnel,
      port: tunnelLocalPort,
    };
  },

  setup: async (_authn, request, options) => {
    // The subscription ID here is used to ensure that the user is logged in to the correct tenant/directory.
    // As long as a subscription ID in the correct tenant is provided, this will work; it need not be the same
    // subscription as which contains the Bastion host or the target VM.
    const linuxUserName = await azSetSubscription(request, options);

    if (linuxUserName !== request.linuxUserName) {
      throw `Azure CLI login returned a different user name than expected. Expected: ${request.linuxUserName}, Actual: ${linuxUserName}`;
    }

    const { path: keyPath, cleanup: sshKeyPathCleanup } =
      await createTempDirectoryForKeys();

    const wrappedCreateCertAndTunnel = async () => {
      try {
        await generateSshKeyAndAzureAdCert(keyPath, options);
        return await trySpawnBastionTunnel(request, options);
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
        `CertificateFile=${sshCertificateKeyPath}`,

        // Because we connect to the Azure Network Bastion tunnel via a local port instead of a ProxyCommand, every
        // instance connected to will appear to `ssh` to be the same host but presenting a different host key (i.e.,
        // `ssh` always connects to localhost but each VM will present its own host key), which will trigger MITM attack
        // warnings. We disable host key checking to avoid this. This is ordinarily very dangerous, but in this case,
        // security of the connection is ensured by the Azure Bastion Network tunnel, which utilizes HTTPS and thus has
        // its own MITM protection.
        "StrictHostKeyChecking=no",
        "UserKnownHostsFile=/dev/null",
      ],
      identityFile: sshPrivateKeyPath,
      port: tunnelLocalPort,
      teardown,
    };
  },

  requestToSsh: (request) => {
    const { bastionHost, jumpHost } = request.permission;
    if (!bastionHost) {
      throw jumpHost
        ? "This SSH session uses an Azure jump host, which is not yet supported by this CLI version. Please request a Bastion-based session or retry after upgrading."
        : "Backend did not provide an Azure Bastion host for SSH session.";
    }
    return {
      type: "azure",
      id: "localhost",
      ...request.cliLocalData,
      instanceId: request.permission.resource.instanceId,
      subscriptionId: request.permission.resource.subscriptionId,
      instanceResourceGroup: request.permission.resource.resourceGroupId,
      bastionId: bastionHost.id,
      directoryId: request.generated.directoryId,
    };
  },
};
