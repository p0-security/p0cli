/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import * as crypto from "crypto";

function toUInt32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n, 0);
  return b;
}

const sshString = (b: string): Buffer => {
  return Buffer.concat([toUInt32(b.length), Buffer.from(b)]);
};

/**
 * Convert a Buffer to a multiple precision integer (mpint)
 *
 * mpints are represented in two's complement format,
 * stored as a string, 8 bits per byte, MSB first.
 *
 * https://datatracker.ietf.org/doc/html/rfc4251#section-5
 */
function toMultiplePrecisionInteger(raw: Buffer): Buffer {
  // strip all leading zeros
  let i = 0;
  while (i < raw.length && raw[i] === 0) i++;
  let b = raw.slice(i);
  // zero -> single 0x00
  if (b.length === 0) b = Buffer.from([0]);
  // MSB set -> pad
  if (b[0]! & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return Buffer.concat([toUInt32(b.length), b]);
}

/**
 * Convert a crypto.KeyObject RSA public key to OpenSSH "ssh-rsa ..."
 *
 *  The "blob" is a sequence of length-prefixed strings:
 *   string "ssh-rsa"
 *   mpint e
 *   mpint n
 *
 * After building that blob, you base64 it and prepend ssh-rsa (plus an optional comment).
 * See https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
 */
export function toOpenSshFormat(
  keyObject: crypto.KeyObject,
  comment = "p0-generated-key"
): string {
  const jwk = keyObject.export({ format: "jwk" }) as JsonWebKey;
  if (jwk.kty !== "RSA" || !jwk.n || !jwk.e) {
    throw new Error("Expected an RSA public key (JWK with n and e).");
  }

  const nBuffer = Buffer.from(jwk.n, "base64url");
  const eBuffer = Buffer.from(jwk.e, "base64url");

  const keyType = "ssh-rsa";
  const blob = Buffer.concat([
    sshString(keyType),
    toMultiplePrecisionInteger(eBuffer),
    toMultiplePrecisionInteger(nBuffer),
  ]);

  return `${keyType} ${blob.toString("base64")}${comment ? " " + comment : ""}`;
}
