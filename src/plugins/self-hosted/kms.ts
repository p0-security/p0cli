/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { asyncSpawn } from "../../common/subprocess";
import { print2 } from "../../drivers/stdio";
import { gcloudCommandArgs } from "../google/util";

/**
 * Signs the given data string using a Google Cloud KMS asymmetric signing key.
 *
 * Requires the gcloud CLI to be installed and authenticated via `gcloud auth login`.
 *
 * @param data - The data to sign (the raw OpenSSH public key string).
 * @param kmsKeyResourceName - Full KMS key version resource name, e.g.
 *   `projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V`
 * @returns Base64-encoded signature as returned by the KMS API.
 */
export const signWithKms = async (
  data: string,
  kmsKeyResourceName: string,
  options?: { debug?: boolean }
): Promise<string> => {
  const debug = options?.debug ?? false;

  // Force debug=false to avoid printing the access token
  const { command: accessTokenCommand, args: accessTokenArgs } =
    gcloudCommandArgs(["auth", "print-access-token"]);
  const accessToken = await asyncSpawn(
    { debug: false },
    accessTokenCommand,
    accessTokenArgs
  );

  if (debug) {
    print2(
      `Signing public key with KMS key: ${kmsKeyResourceName} (token: ${accessToken.slice(0, 10)}...)`
    );
  }

  const encodedData = Buffer.from(data, "utf-8").toString("base64");

  const url = `https://cloudkms.googleapis.com/v1/${kmsKeyResourceName}:asymmetricSign`;
  const response = await fetch(url, {
    method: "POST",
    body: JSON.stringify({ data: encodedData }),
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
  });

  if (!response.ok) {
    if (debug) {
      print2(`KMS HTTP error ${response.status}: ${await response.text()}`);
    }
    if (response.status === 401) {
      throw `Authentication failed. Please login to Google Cloud CLI with 'gcloud auth login'`;
    }
    throw `KMS signing failed.`;
  }

  const result: { signature: string } = await response.json();

  if (debug) {
    print2(`KMS signature obtained (${result.signature.length} chars)`);
  }

  return result.signature;
};
