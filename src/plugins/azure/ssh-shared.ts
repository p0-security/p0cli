/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
// Import types only: a value import would create a require cycle back through
// commands/shared/ssh.ts -> ssh-bastion.ts, which spreads azureSshProviderBase
// at module load time.
import { type SshAdditionalSetup } from "../../commands/shared/ssh";
import { print2 } from "../../drivers/stdio";
import { SshProvider } from "../../types/ssh";
import { exec, osSafeCommand } from "../../util";
import { createTempDirectoryForKeys, isSudoCommand } from "../ssh/shared";
import {
  azAccountClearCommand,
  azAccountSetCommand,
  azLoginCommand,
  azSetSubscription,
} from "./auth";
import { ensureAzInstall } from "./install";
import {
  AzureLocalData,
  AzureSshPermissionSpec,
  AzureSshRequest,
} from "./types";
import path from "node:path";

// We pass in the name of the certificate file to generate
export const AD_CERT_FILENAME = "p0cli-azure-ad-ssh-cert.pub";

// The `az ssh cert` command manages key generation, and generates SSH RSA keys with the standard names
export const AD_SSH_KEY_PRIVATE = "id_rsa";

// Azure user access is subject to significant propagation delays of up to 10 minutes
// when elevating access to sudo. If the user starts with sudo access, there is no
// propagation delay. The typical time for propagation is less than 1 minute, but
// we want to be safe, so we set the timeout to 3 minutes. With a longer timeout a
// user doesn't have to retry the command too many times.
const PROPAGATION_TIMEOUT_LIMIT_MS = 3 * 60 * 1000;

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

export const azSshCertCommand = (keyPath: string) =>
  osSafeCommand("az", [
    "ssh",
    "cert",
    "--file",
    path.join(keyPath, AD_CERT_FILENAME),
  ]);

export const generateSshKeyAndAzureAdCert = async (
  keyPath: string,
  options: { debug?: boolean } = {}
) => {
  const { debug } = options;

  if (debug) print2("Generating Azure AD SSH certificate...");

  try {
    const { command, args } = azSshCertCommand(keyPath);
    const { stdout, stderr } = await exec(command, args, { check: true });

    if (debug) {
      print2(stdout);
      print2(stderr);
    }
  } catch (error: any) {
    print2(error.stdout);
    print2(error.stderr);
    throw `Failed to generate Azure AD SSH certificate: ${error}`;
  }
};

/** The commands to log in to Azure and generate the SSH certificate; shared by
 * every Azure SSH provider's reproCommands. Providers append their own
 * connection (e.g. tunnel) commands. */
export const azureSshLoginReproCommands = (
  request: Pick<AzureSshRequest, "directoryId" | "subscriptionId">,
  additionalData?: SshAdditionalSetup
): string[] => {
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
    // additionalData isn't present (which it always should be for Azure SSH providers), we'll use the user's home
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

/** SshProvider members shared by every Azure SSH provider, regardless of how
 * the connection to the target is established (Bastion tunnel, jump host, ...) */
export const azureSshProviderBase = {
  // TODO: Natively support Azure login in P0 CLI
  cloudProviderLogin: async () => {
    // Login is handled as part of the provider's setup
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
} satisfies Partial<
  SshProvider<AzureSshPermissionSpec, AzureLocalData, AzureSshRequest>
>;
