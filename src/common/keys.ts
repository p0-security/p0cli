/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../drivers/stdio";
import { P0_PATH } from "../util";
import * as crypto from "crypto";
import * as fs from "fs/promises";
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
    const keyPair = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });

    const privateKey = keyPair.privateKey.export({
      type: "pkcs8",
      format: "pem",
    }) as string;
    const publicKey = toOpenSshFormat(keyPair.publicKey);

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

/**
 * Convert a crypto.KeyObject RSA public key to OpenSSH format
 */
const toOpenSshFormat = (keyObject: crypto.KeyObject): string => {
  // Export the key in JWK format to get n and e values
  const jwk = keyObject.export({ format: "jwk" });

  // Convert base64url to buffer
  const nBuffer = Buffer.from(jwk.n!, "base64url");
  const eBuffer = Buffer.from(jwk.e!, "base64url");

  // Create SSH wire format
  const keyType = "ssh-rsa";
  const keyTypeBuffer = Buffer.from(keyType);

  // SSH wire format: [key_type_len][key_type][e_len][e][n_len][n]
  const keyTypeLen = Buffer.alloc(4);
  keyTypeLen.writeUInt32BE(keyTypeBuffer.length, 0);

  const eLen = Buffer.alloc(4);
  eLen.writeUInt32BE(eBuffer.length, 0);

  const nLen = Buffer.alloc(4);
  nLen.writeUInt32BE(nBuffer.length, 0);

  const sshWireFormat = Buffer.concat([
    keyTypeLen,
    keyTypeBuffer,
    eLen,
    eBuffer,
    nLen,
    nBuffer,
  ]);

  // Base64 encode and format as OpenSSH key
  const base64Key = sshWireFormat.toString("base64");
  return `${keyType} ${base64Key} p0-generated-key`;
};

export const KNOWN_HOSTS_DIR = path.join(P0_KEY_FOLDER, "known_hosts");
export const KNOWN_HOSTS_PATH = path.join(P0_KEY_FOLDER, "known_hosts_config");

/**
 * Save host keys to separate files in the P0 SSH known_hosts directory
 * - Creates a separate file for each host in known_hosts/ directory
 * - Replaces the entire file with the most up-to-date host keys for that host
 * - Creates an SSH config file that includes all host key files
 */
export const saveHostKeys = async (
  instanceId: string,
  hostKeys: string[],
  options?: { debug?: boolean }
): Promise<string | undefined> => {
  if (!hostKeys || hostKeys.length === 0) {
    if (options?.debug) {
      print2("No host keys provided, skipping saving of host keys");
    }
    return;
  }

  if (options?.debug) {
    print2(`Processing ${hostKeys.length} host keys`);
    print2(`Known hosts directory: ${KNOWN_HOSTS_DIR}`);
  }

  await fs.mkdir(KNOWN_HOSTS_DIR, { recursive: true });

  const hostFilePath = getKnownHostsFilePath(instanceId);

  // Always overwrite the file with the latest host keys
  if (await fileExists(hostFilePath)) {
    if (options?.debug) {
      print2(
        `Host keys file for instance ${instanceId} already exists, overwriting`
      );
    }
  }

  const content = hostKeys.join("\n") + "\n";
  await fs.writeFile(hostFilePath, content, { mode: 0o600 });

  if (options?.debug) {
    print2(
      `Saved ${hostKeys.length} host keys for instance ${instanceId} to ${hostFilePath}`
    );
  }
  return hostFilePath;
};

/**
 * Get the known_hosts file path for a specific instance ID
 */
export const getKnownHostsFilePath = (instanceId: string): string => {
  const sanitizedId = instanceId.replace(/[^a-zA-Z0-9.-]/g, "_");
  return path.join(KNOWN_HOSTS_DIR, sanitizedId);
};
