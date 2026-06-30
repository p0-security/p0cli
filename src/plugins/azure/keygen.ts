/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { exec, osSafeCommand } from "../../util";
import { createTempDirectoryForKeys } from "../ssh/shared";
import { azSetSubscription } from "./auth";
import { AzureSshRequest } from "./types";
import path from "node:path";

// We pass in the name of the certificate file to generate
export const AD_CERT_FILENAME = "p0cli-azure-ad-ssh-cert.pub";

// The `az ssh cert` command manages key generation, and generates SSH RSA keys with the standard names
export const AD_SSH_KEY_PRIVATE = "id_rsa";

export const azSshCertCommand = (keyPath: string) =>
  osSafeCommand("az", [
    "ssh",
    "cert",
    "--file",
    path.join(keyPath, AD_CERT_FILENAME),
  ]);

export type AzureSshKeys = {
  privateKeyPath: string;
  certificatePath: string;
  cleanup: () => Promise<void>;
};

/** Mints a fresh SSH key pair and Azure AD certificate in a temporary directory.
 *
 * This is the single entry point for creating any Azure SSH credential the CLI
 * needs, whether for the target hop or for an intermediate jump-host hop. The
 * caller owns the returned `cleanup`.
 */
export const generateAzureSshKeys = async (
  request: AzureSshRequest,
  options: { debug?: boolean } = {}
): Promise<AzureSshKeys> => {
  // The subscription ID here is used to ensure that the user is logged in to the correct tenant/directory.
  // As long as a subscription ID in the correct tenant is provided, this will work; it need not be the same
  // subscription as which contains the Bastion host or the target VM.
  const linuxUserName = await azSetSubscription(request, options);

  if (linuxUserName !== request.linuxUserName) {
    throw `Azure CLI login returned a different user name than expected. Expected: ${request.linuxUserName}, Actual: ${linuxUserName}`;
  }

  const { path: keyPath, cleanup } = await createTempDirectoryForKeys();

  try {
    await generateSshKeyAndAzureAdCert(keyPath, options);
  } catch (error: any) {
    await cleanup();
    throw error;
  }

  return {
    privateKeyPath: path.join(keyPath, AD_SSH_KEY_PRIVATE),
    certificatePath: path.join(keyPath, AD_CERT_FILENAME),
    cleanup,
  };
};

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
