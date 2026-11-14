/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { isRecord, isTokenText } from "./guards";
import { assertSameOrigin } from "./server-url";
import type { GitSession } from "./store";

export const GIT_CLIENT_ID = "p0-git";

const SETUP_CODE_GRANT_TYPE = "urn:p0:params:oauth:grant-type:setup-code";

// Must stay below the stale time of the store lock.
const REQUEST_TIMEOUT_MS = 10_000;

const SESSION_ID = /^[\w.-]{1,256}$/;
const RESERVED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/** Thrown when the server refuses the code or the refresh token. */
export class GitGrantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GitGrantError";
  }
}

type TokenReply = {
  accessToken: string;
  refreshToken: string;
  /** Unix time in milliseconds */
  accessExpiresAt: number;
  repositories: string[];
};

// A redirect would send the code or the refresh token to the redirect target.
const request = (url: string, init: RequestInit = {}) =>
  fetch(url, {
    ...init,
    redirect: "error",
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });

async function getJson(url: string): Promise<Record<string, unknown>> {
  const response = await request(url);
  if (!response.ok) throw `Failed to read ${url} (${response.status})`;
  const body: unknown = await response.json();
  if (!isRecord(body)) throw `Unexpected reply from ${url}`;
  return body;
}

/** The token endpoint from the server's OAuth metadata. It must be on the
 * server's origin. */
export async function discoverTokenEndpoint(
  serverUrl: string
): Promise<string> {
  const resource = await getJson(
    `${serverUrl}/.well-known/oauth-protected-resource`
  );
  const [issuer] = Array.isArray(resource.authorization_servers)
    ? resource.authorization_servers
    : [];
  if (typeof issuer !== "string") {
    throw `No authorization server in the metadata of ${serverUrl}`;
  }
  assertSameOrigin(serverUrl, issuer);
  const metadata = await getJson(
    `${issuer.replace(/\/+$/, "")}/.well-known/oauth-authorization-server`
  );
  if (
    metadata.issuer !== issuer ||
    typeof metadata.token_endpoint !== "string"
  ) {
    throw `The authorization server metadata of ${issuer} is not valid`;
  }
  assertSameOrigin(serverUrl, metadata.token_endpoint);
  return metadata.token_endpoint;
}

function parseTokenReply(body: Record<string, unknown>): TokenReply {
  const { access_token, refresh_token, expires_in, repositories } = body;
  if (
    !isTokenText(access_token) ||
    !isTokenText(refresh_token) ||
    typeof expires_in !== "number"
  ) {
    throw "Unexpected token reply from the P0 gateway";
  }
  return {
    accessToken: access_token,
    refreshToken: refresh_token,
    accessExpiresAt: Date.now() + expires_in * 1000,
    repositories: Array.isArray(repositories)
      ? repositories.filter((name): name is string => typeof name === "string")
      : [],
  };
}

async function requestToken(
  tokenEndpoint: string,
  params: Record<string, string>
): Promise<TokenReply> {
  const response = await request(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ...params, client_id: GIT_CLIENT_ID }),
  });
  const body: unknown = await response.json().catch(() => undefined);
  if (!isRecord(body)) {
    throw `Unexpected reply from the P0 gateway (${response.status})`;
  }
  if (body.error === "invalid_grant") {
    throw new GitGrantError(String(body.error_description ?? "invalid_grant"));
  }
  if (!response.ok) {
    throw `The P0 gateway refused the token request (${response.status}): ${String(body.error_description ?? body.error)}`;
  }
  return parseTokenReply(body);
}

export const redeemSetupCode = (tokenEndpoint: string, code: string) =>
  requestToken(tokenEndpoint, { grant_type: SETUP_CODE_GRANT_TYPE, code });

export const refreshSession = (session: GitSession) =>
  requestToken(session.tokenEndpoint, {
    grant_type: "refresh_token",
    refresh_token: session.refreshToken,
  });

/** The `sid` claim of a JWT. The signature is not checked. */
export function sessionIdOf(accessToken: string): string {
  const [, payload] = accessToken.split(".");
  const claims: unknown = payload
    ? JSON.parse(Buffer.from(payload, "base64url").toString("utf-8"))
    : undefined;
  const sid = isRecord(claims) ? claims.sid : undefined;
  if (
    typeof sid !== "string" ||
    !SESSION_ID.test(sid) ||
    RESERVED_KEYS.has(sid)
  ) {
    throw "The git access token has no valid Session ID";
  }
  return sid;
}
