/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { exec } from "../../util";
import path from "node:path";

// We pass in the name of the certificate file to generate
export const AD_CERT_FILENAME = "p0cli-azure-ad-ssh-cert.pub";

// The `az ssh cert` command manages key generation, and generates SSH RSA keys with the standard names
export const AD_SSH_KEY_PRIVATE = "id_rsa";

export const azSshCertCommand = (keyPath: string) => ({
  command: "az",
  args: ["ssh", "cert", "--file", path.join(keyPath, AD_CERT_FILENAME)],
});

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
