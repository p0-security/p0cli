/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { isSudoCommand } from "../../commands/shared/ssh";
import { SshProvider } from "../../types/ssh";
import { createTempDirectoryForKeys } from "../ssh/shared";
import {
  azAccountClearCommand,
  azAccountSetCommand,
  azLoginCommand,
  azSetSubscription,
} from "./auth";
import { ensureAzInstall } from "./install";
import {
  AD_CERT_FILENAME,
  AD_SSH_KEY_PRIVATE,
  azSshCertCommand,
  generateSshKeyAndAzureAdCert,
} from "./keygen";
import { azBastionTunnelCommand, trySpawnBastionTunnel } from "./tunnel";
import {
  AzureLocalData,
  AzureSshPermissionSpec,
  AzureSshRequest,
} from "./types";
import path from "node:path";

const unprovisionedAccessPatterns = [
  {
    // The output of `sudo -v` when the user is not allowed to run sudo
    pattern: /Sorry, user .+ may not run sudo on .+/,
  },
] as const;

const provisionedAccessPatterns = [
  {
    pattern: /sudo: a password is required/,
  },
] as const;

// Azure user access is subject to significant propagation delays of up to 10 minutes
// when elevating access to sudo. If the user starts with sudo access, there is no
// propagation delay. The typical time for propagation is less than 1 minute, but
// we want to be safe, so we set the timeout to 3 minutes. With a longer timeout a
// user doesn't have to retry the command too many times.
const PROPAGATION_TIMEOUT_LIMIT_MS = 3 * 60 * 1000;

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

  preTestAccessPropagationArgs: (cmdArgs) => {
    if (isSudoCommand(cmdArgs)) {
      return {
        ...cmdArgs,
        // `sudo -v` prints `Sorry, user <user> may not run sudo on <hostname>.` to stderr when user is not a sudoer.
        // we have to use `-n` flag to avoid the oauth prompt on azure cli.
        command: "sudo",
        arguments: ["-nv"],
      };
    }
    return undefined;
  },

  proxyCommand: (_, port) => ["nc", "localhost", port ?? "22"],

  reproCommands: (request, additionalData) => {
    const { command: azAccountClearExe, args: azAccountClearArgs } =
      azAccountClearCommand();
    const { command: azLoginExe, args: azLoginArgs } = azLoginCommand(
      request.directoryId
    );
    const { command: azAccountSetExe, args: azAccountSetArgs } =
      azAccountSetCommand(request.subscriptionId);

    const getKeyPath = () => {
      // Use the same key path as the one generated in setup() so it matches the ssh command that is generated
      // elsewhere. It'll be an annoying long temporary directory name, but it strictly will work for reproduction. If
      // additionalData isn't present (which it always should be for the azureSshProvider), we'll use the user's home
      // directory.
      if (additionalData?.identityFile) {
        return path.dirname(additionalData.identityFile);
      } else {
        const basePath = process.env.HOME || process.env.USERPROFILE || "";
        return path.join(basePath, "p0cli-azure-ssh-keys");
      }
    };

    const keyPath = getKeyPath();

    const { command: azCertGenExe, args: azCertGenArgs } =
      azSshCertCommand(keyPath);

    // If additionalData is undefined (which, again, should be never), use the default port for Azure Network Bastion
    // tunnels instead of generating a random one
    const { command: azTunnelExe, args: azTunnelArgs } = azBastionTunnelCommand(
      request,
      additionalData?.port ?? "50022"
    );

    return [
      `${azAccountClearExe} ${azAccountClearArgs.join(" ")}`,
      `${azLoginExe} ${azLoginArgs.join(" ")}`,
      `${azAccountSetExe} ${azAccountSetArgs.join(" ")}`,
      `mkdir ${keyPath}`,
      `${azCertGenExe} ${azCertGenArgs.join(" ")}`,
      `${azTunnelExe} ${azTunnelArgs.join(" ")}`,
    ];
  },

  generateKeys: async (_authn, request, options: { debug?: boolean } = {}) => {
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

  setupProxy: async (
    request: AzureSshRequest,
    options: { debug?: boolean; abortController: AbortController }
  ) => {
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

  requestToSsh: (request) => ({
    type: "azure",
    id: "localhost",
    ...request.cliLocalData,
    instanceId: request.permission.resource.instanceId,
    subscriptionId: request.permission.resource.subscriptionId,
    instanceResourceGroup: request.permission.resource.resourceGroupId,
    bastionId: request.permission.bastionHostId,
    directoryId: request.generated.directoryId,
  }),

  unprovisionedAccessPatterns,
  provisionedAccessPatterns,

  toCliRequest: async (request) => {
    return {
      ...request,
      cliLocalData: {
        linuxUserName: request.generated.linuxUserName ?? request.principal,
      },
    };
  },
};
