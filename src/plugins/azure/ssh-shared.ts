/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  CommandArgs,
  isSudoCommand,
  SshAdditionalSetup,
} from "../../commands/shared/ssh";
import { PermissionRequest } from "../../types/request";
import {
  azAccountClearCommand,
  azAccountSetCommand,
  azLoginCommand,
} from "./auth";
import { ensureAzInstall } from "./install";
import { azSshCertCommand } from "./keygen";
import { AzureSsh, AzureSshPermissionSpec, AzureSshRequest } from "./types";
import path from "node:path";

export const AZURE_SUDO_NOT_ALLOWED_PATTERN = {
  // The output of `sudo -v` when the user is not allowed to run sudo
  pattern: /Sorry, user .+ may not run sudo on .+/,
} as const;

// Azure user access is subject to significant propagation delays of up to 10 minutes
// when elevating access to sudo. If the user starts with sudo access, there is no
// propagation delay. The typical time for propagation is less than 1 minute, but
// we want to be safe, so we set the timeout to 3 minutes. With a longer timeout a
// user doesn't have to retry the command too many times.
const PROPAGATION_TIMEOUT_LIMIT_MS = 3 * 60 * 1000;

/** Provider behavior common to both Azure connection methods (Azure Bastion
 * tunnel and SSH jump host); spread into each provider's object literal. */
export const azureSshProviderBase = {
  // TODO: Natively support Azure login in P0 CLI
  cloudProviderLogin: async () => {
    // Login is handled as part of setup()
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

  preTestAccessPropagationArgs: (cmdArgs: CommandArgs) => {
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

  provisionedAccessPatterns: [
    {
      pattern: /sudo: a password is required/,
    },
  ] as const,

  toCliRequest: async (request: PermissionRequest<AzureSshPermissionSpec>) => {
    return {
      ...request,
      cliLocalData: {
        linuxUserName: request.generated.linuxUserName ?? request.principal,
      },
    };
  },
};

/** The provider-agnostic part of translating a backend Azure permission into a
 * CLI SSH request; each provider supplies the connection-method-specific `id`. */
export const azureRequestToSshBase = (request: AzureSsh) => {
  const { permission } = request;
  const { jumpHost, bastionHost, resource } = permission;

  return {
    type: "azure" as const,
    ...request.cliLocalData,
    instanceId: resource.instanceId,
    subscriptionId: resource.subscriptionId,
    instanceResourceGroup: resource.resourceGroupId,
    directoryId: request.generated.directoryId,
    bastionId: bastionHost?.id,
    jumpHost,
    privateIp: resource.networkInterface.privateIp,
  };
};

/** The login and certificate-generation steps shared by every Azure repro
 * recipe; the Bastion provider appends its tunnel command to these. */
export const azureReproBaseCommands = (
  request: AzureSshRequest,
  additionalData?: SshAdditionalSetup
) => {
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
    // additionalData isn't present (which it always should be for the Azure providers), we'll use the user's home
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

  return [
    `${azAccountClearExe} ${azAccountClearArgs.join(" ")}`,
    `${azLoginExe} ${azLoginArgs.join(" ")}`,
    `${azAccountSetExe} ${azAccountSetArgs.join(" ")}`,
    `mkdir ${keyPath}`,
    `${azCertGenExe} ${azCertGenArgs.join(" ")}`,
  ];
};
