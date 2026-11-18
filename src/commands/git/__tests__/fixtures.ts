/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { GitSession } from "../store";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

export const SERVER = "https://gateway.example.com/mcps/github";
export const ISSUER = "https://gateway.example.com";
export const TOKEN_ENDPOINT = `${ISSUER}/token`;

/** An unsigned JWT with a `sid` claim. */
export const accessTokenFor = (sid: string, n = 0) =>
  [
    Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url"),
    Buffer.from(JSON.stringify({ sid, n })).toString("base64url"),
    "",
  ].join(".");

export const session = (
  sid: string,
  overrides: Partial<GitSession> = {}
): GitSession => ({
  serverUrl: SERVER,
  tokenEndpoint: TOKEN_ENDPOINT,
  accessToken: accessTokenFor(sid),
  accessExpiresAt: Date.now() + 60 * 60 * 1000,
  refreshToken: `refresh-${sid}`,
  ...overrides,
});

export const makeTempDir = () =>
  fs.mkdtemp(path.join(os.tmpdir(), "p0-git-test-"));

export const tokenReply = (sid: string, n: number, repositories?: string[]) =>
  jsonResponse({
    access_token: accessTokenFor(sid, n),
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: `refresh-${sid}-${n}`,
    ...(repositories && { repositories }),
  });
