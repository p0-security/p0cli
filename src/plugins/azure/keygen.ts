/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { exec } from "../../util";
import path from "node:path";
import tmp from "tmp-promise";

// We pass in the name of the certificate file to generate
export const AD_CERT_FILENAME = "p0cli-azure-ad-ssh-cert.pub";

// The `az ssh cert` command manages key generation, and generates SSH RSA keys with the standard names
export const AD_SSH_KEY_PRIVATE = "id_rsa";

export const createTempDirectoryForKeys = async (): Promise<{
  path: string;
  cleanup: () => Promise<void>;
}> => {
  // unsafeCleanup lets us delete the directory even if there are still files in it, which is fine since the
  // files are no longer needed once we've authenticated to the remote system.
  const { path, cleanup } = await tmp.dir({
    mode: 0o700,
    prefix: "p0cli-",
    unsafeCleanup: true,
  });

  return { path, cleanup };
};

export const generateSshKeyAndAzureAdCert = async (keyPath: string) => {
  try {
    await exec(
      "az",
      ["ssh", "cert", "--file", path.join(keyPath, AD_CERT_FILENAME)],
      { check: true }
    );
  } catch (error: any) {
    print2(error.stdout);
    print2(error.stderr);
    throw `Failed to generate Azure AD SSH certificate: ${error}`;
  }
};
