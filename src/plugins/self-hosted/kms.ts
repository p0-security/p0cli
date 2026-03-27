/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { OIDC_HEADERS } from "../../common/auth/oidc";
import { urlEncode, validateResponse } from "../../common/fetch";
import { print2 } from "../../drivers/stdio";
import { Identity } from "../../types/identity";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";
const TOKEN_EXCHANGE_GRANT_TYPE =
  "urn:ietf:params:oauth:grant-type:token-exchange";

/**
 * Exchanges an OIDC id_token for a federated GCP access token via Google STS.
 * Uses Workload Identity Federation direct auth (no service account).
 * The WIF pool must be configured to accept tokens from the OIDC provider directly.
 */
const exchangeOidcForGcpToken = async (
  oidcToken: string,
  wifPool: string
): Promise<string> => {
  const response = await fetch("https://sts.googleapis.com/v1/token", {
    method: "POST",
    headers: OIDC_HEADERS,
    body: urlEncode({
      audience: wifPool,
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      requested_token_type: ACCESS_TOKEN_TYPE,
      subject_token: oidcToken,
      subject_token_type: ID_TOKEN_TYPE,
      scope: "https://www.googleapis.com/auth/cloud-platform",
    }),
  });

  await validateResponse(response);
  const data: { access_token: string } = await response.json();
  return data.access_token;
};

/**
 * Signs the given data string using a Google Cloud KMS asymmetric signing key.
 *
 * Authenticates via Workload Identity Federation: sends the user's OIDC
 * id_token directly to Google STS to obtain a federated GCP access token,
 * then uses that to call the KMS API — no gcloud CLI or service account required.
 *
 * @param data - The data to sign (the raw OpenSSH public key string).
 * @param kmsKeyResourceName - Full KMS key version resource name, e.g.
 *   `projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V`
 * @param identity - The user's P0 identity containing OIDC credentials.
 * @param wifPool - The WIF pool resource path, e.g.
 *   `//iam.googleapis.com/projects/P/locations/global/workloadIdentityPools/POOL`
 * @returns Base64-encoded signature as returned by the KMS API.
 */
export const signWithKms = async (
  data: string,
  kmsKeyResourceName: string,
  identity: Identity,
  wifPool: string,
  options?: { debug?: boolean }
): Promise<string> => {
  const debug = options?.debug ?? false;

  const accessToken = await exchangeOidcForGcpToken(
    identity.credential.id_token,
    wifPool
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
      throw `Authentication failed. Please re-authenticate with '${identity.org.slug}' and try again.`;
    }
    throw `KMS signing failed.`;
  }

  const result: { signature: string } = await response.json();

  if (debug) {
    print2(`KMS signature obtained (${result.signature.length} chars)`);
  }

  return result.signature;
};
