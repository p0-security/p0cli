/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import * as crypto from "crypto";

const TOKEN_LIFETIME_SECONDS = 60;

const base64url = (data: Buffer | string): string => {
  const buf = typeof data === "string" ? Buffer.from(data) : data;
  return buf.toString("base64url");
};

/**
 * Sign a short-lived JWT for authenticating to the RDP proxy bastion.
 * Uses RS256 (RSA + SHA-256) with the CLI's existing RSA private key.
 */
export const signProxyToken = (args: {
  principal: string;
  target: string;
  privateKey: string;
}): string => {
  const { principal, target, privateKey } = args;

  const now = Math.floor(Date.now() / 1000);

  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(
    JSON.stringify({
      sub: principal,
      target,
      iat: now,
      exp: now + TOKEN_LIFETIME_SECONDS,
    })
  );

  const signingInput = `${header}.${payload}`;
  const signature = crypto.sign(
    "sha256",
    Buffer.from(signingInput),
    privateKey
  );

  return `${signingInput}.${base64url(signature)}`;
};
