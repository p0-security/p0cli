/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { asyncSpawn } from "../ssh-agent";
import { ImportSshPublicKeyResponse } from "./types";

/**
 * Adds an ssh public key to the user object's sshPublicKeys array in Google Workspace.
 * GCP OS Login uses these public keys to authenticate the user.
 * Importing the same public key multiple times is idempotent.
 *
 * The user account and the access token is retrieved from the gcloud CLI.
 *
 * Returns the posix account to use for SSH access.
 *
 * See https://cloud.google.com/compute/docs/oslogin/rest/v1/users/importSshPublicKey
 */
export const importSshKey = async (
  publicKey: string,
  options?: { debug?: boolean }
) => {
  const debug = options?.debug ?? false;
  const accessToken = await asyncSpawn({ debug }, "gcloud", [
    "auth",
    "print-access-token",
  ]);
  const account = await asyncSpawn({ debug }, "gcloud", [
    "config",
    "get-value",
    "account",
  ]);
  if (debug) {
    print2(
      `Retrieved access token ${accessToken.slice(0, 10)}... for account ${account}`
    );
  }
  const url = `https://oslogin.googleapis.com/v1/users/${account}:importSshPublicKey`;
  const response = await fetch(url, {
    method: "POST",
    // nosemgrep: p0_security.no-stringify-keys
    body: JSON.stringify({
      key: publicKey,
    }),
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
  });
  const data: ImportSshPublicKeyResponse = await response.json();
  if (debug) {
    print2(
      `Login profile for user after importing public key: ${JSON.stringify(data)}`
    );
  }
  const { loginProfile } = data;
  // Find the primary POSIX account for the user, or the first in the array
  const posixAccount =
    loginProfile.posixAccounts.find((account) => account.primary) ||
    loginProfile.posixAccounts[0];
  if (debug) {
    print2(`Picked linux user name: ${posixAccount?.username}`);
  }
  if (!posixAccount) {
    throw "No POSIX accounts configured for the user. Ask your Google Workspace administrator to configure the user's POSIX account.";
  }
  return posixAccount;
};
