/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { SshProvider } from "../../types/ssh";
import { getOperatingSystem } from "../../util";
import { generateAzureSshKeys } from "./keygen";
import {
  AZURE_SUDO_NOT_ALLOWED_PATTERN,
  azureReproBaseCommands,
  azureRequestToSshBase,
  azureSshProviderBase,
} from "./ssh-shared";
import { azBastionTunnelCommand, trySpawnBastionTunnel } from "./tunnel";
import {
  AzureLocalData,
  AzureSshPermissionSpec,
  AzureSshRequest,
} from "./types";

/** Connects to an Azure VM through an Azure Bastion tunnel: a local port is
 * forwarded to the VM's SSH port over the Bastion host's HTTPS tunnel. */
export const azureBastionSshProvider: SshProvider<
  AzureSshPermissionSpec,
  AzureLocalData,
  AzureSshRequest
> = {
  ...azureSshProviderBase,

  proxyCommand: (_, port) => {
    const targetPort = port ?? "22";
    // Connect through the local tunnel.
    // On Windows, use ncat (from nmap). On Unix/Mac, use nc.
    // Both have the same command line syntax: command localhost port
    const command = getOperatingSystem() === "win" ? "ncat" : "nc";
    return [command, "localhost", targetPort];
  },

  reproCommands: (request, additionalData) => {
    // If additionalData is undefined (which, again, should be never), use the default port for Azure Network Bastion
    // tunnels instead of generating a random one
    const { command: azTunnelExe, args: azTunnelArgs } = azBastionTunnelCommand(
      request,
      additionalData?.port ?? "50022"
    );

    return [
      ...azureReproBaseCommands(request, additionalData),
      `${azTunnelExe} ${azTunnelArgs.join(" ")}`,
    ];
  },

  generateKeys: async (_authn, request, options) => {
    const { privateKeyPath, certificatePath } = await generateAzureSshKeys(
      request,
      options
    );
    return { privateKeyPath, certificatePath };
  },

  setupProxy: async (_authn, request, options) => {
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
    const keys = await generateAzureSshKeys(request, options);

    const tunnel = await trySpawnBastionTunnel(request, options).catch(
      async (error: any) => {
        await keys.cleanup();
        throw error;
      }
    );

    const teardown = async () => {
      await tunnel.killTunnel();
      await keys.cleanup();
    };

    return {
      sshOptions: [
        `CertificateFile=${keys.certificatePath}`,

        // Because we connect to the Azure Network Bastion tunnel via a local port instead of a ProxyCommand, every
        // instance connected to will appear to `ssh` to be the same host but presenting a different host key (i.e.,
        // `ssh` always connects to localhost but each VM will present its own host key), which will trigger MITM attack
        // warnings. We disable host key checking to avoid this. This is ordinarily very dangerous, but in this case,
        // security of the connection is ensured by the Azure Bastion Network tunnel, which utilizes HTTPS and thus has
        // its own MITM protection.
        "StrictHostKeyChecking=no",
        "UserKnownHostsFile=/dev/null",
      ],
      identityFile: keys.privateKeyPath,
      port: tunnel.tunnelLocalPort,
      teardown,
    };
  },

  requestToSsh: (request) => {
    const base = azureRequestToSshBase(request);

    if (!base.bastionId) {
      throw "This Azure VM is not reachable: no jump host or bastion host is associated with it.";
    }

    // The Bastion tunnel is a local port forward, so the connection is always made to localhost.
    return { ...base, id: "localhost" };
  },

  unprovisionedAccessPatterns: [AZURE_SUDO_NOT_ALLOWED_PATTERN],
};
