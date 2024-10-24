/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { P0_PATH } from "../util";
import * as fs from "fs/promises";
import forge from "node-forge";
import * as path from "path";

export const P0_KEY_FOLDER = path.join(P0_PATH, "ssh");
export const PUBLIC_KEY_PATH = path.join(P0_KEY_FOLDER, "id_rsa.pub");
export const PRIVATE_KEY_PATH = path.join(P0_KEY_FOLDER, "id_rsa");

/**
 * Search for a cached key pair, or create a new one if not found
 */
export const createKeyPair = async (): Promise<{
  publicKey: string;
  privateKey: string;
}> => {
  if (
    (await fileExists(PUBLIC_KEY_PATH)) &&
    (await fileExists(PRIVATE_KEY_PATH))
  ) {
    const publicKey = await fs.readFile(PUBLIC_KEY_PATH, "utf8");
    const privateKey = await fs.readFile(PRIVATE_KEY_PATH, "utf8");

    return { publicKey, privateKey };
  } else {
    const rsaKeyPair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    const privateKey = forge.pki.privateKeyToPem(rsaKeyPair.privateKey);
    const publicKey = forge.ssh.publicKeyToOpenSSH(rsaKeyPair.publicKey);

    await fs.mkdir(path.dirname(PUBLIC_KEY_PATH), { recursive: true });
    await fs.writeFile(PUBLIC_KEY_PATH, publicKey, { mode: 0o600 });
    await fs.writeFile(PRIVATE_KEY_PATH, privateKey, { mode: 0o600 });
    return { publicKey, privateKey };
  }
};

const fileExists = async (path: string) => {
  try {
    await fs.access(path);
    return true;
  } catch (error) {
    return false;
  }
};
