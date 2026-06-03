/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { OIDC_HEADERS } from "../../common/auth/oidc";
import { urlEncode } from "../../common/fetch";
import { getClientId, getProviderDomain } from "../../types/authUtils";
import { Identity } from "../../types/identity";
import { TokenResponse } from "../../types/oidc";
import { print2 } from "../stdio";

export const REFRESH_FAILED = "REFRESH_FAILED" as const;

export type RefreshError = {
  code: typeof REFRESH_FAILED;
  reason:
    | "http_error"
    | "missing_id_token"
    | "missing_provider_config"
    | "network_error"
    | "no_refresh_token";
  cause?: unknown;
  detail?: string;
};

const refreshError = (
  reason: RefreshError["reason"],
  extra?: { cause?: unknown; detail?: string }
): RefreshError => ({ code: REFRESH_FAILED, reason, ...extra });

/**
 * Merge a newly-issued credential from the refresh-token grant with the
 * previously-stored credential. Note, not all fields are included in the
 * refreshed token, and thus must be carried forward from the previous/original token.
 **/
export const mergeRefreshedCredential = (
  previous: TokenResponse,
  refreshed: TokenResponse
): TokenResponse => ({
  ...previous,
  ...refreshed,
  refresh_token: refreshed.refresh_token ?? previous.refresh_token,
  device_secret: previous.device_secret, // never returned on refresh
  // RFC 6749 §6: omitted scope on refresh means "identical to original grant"
  scope: refreshed.scope ?? previous.scope,
  token_type: refreshed.token_type ?? previous.token_type,
});

/**
 * Exchange the stored refresh_token for a new access/id token pair against
 * Okta's /oauth2/v1/token endpoint.
 *
 * On any failure, throws a RefreshError. Callers are expected to
 * catch this and fall through to the device-flow path.
 */
export const refreshOktaTokens = async (
  identity: Identity,
  options?: { debug?: boolean }
): Promise<TokenResponse> => {
  const refresh_token = identity.credential.refresh_token;
  if (!refresh_token) throw refreshError("no_refresh_token");

  const providerDomain = getProviderDomain(identity.org);
  const clientId = getClientId(identity.org);
  if (!providerDomain || !clientId) {
    throw refreshError("missing_provider_config");
  }

  const url = `https://${providerDomain}/oauth2/v1/token`;
  const init: RequestInit = {
    method: "POST",
    headers: OIDC_HEADERS,
    body: urlEncode({
      grant_type: "refresh_token",
      client_id: clientId,
      refresh_token,
    }),
  };

  let response: Response;
  try {
    response = await fetch(url, init);
  } catch (e) {
    throw refreshError("network_error", { cause: e });
  }

  if (!response.ok) {
    if (options?.debug) {
      const detail = await response.text().catch(() => undefined);
      print2(
        `Okta refresh-token grant failed: ${response.status} ${response.statusText} ${detail ?? ""}`
      );
    }
    throw refreshError("http_error", {
      detail: `${response.status} ${response.statusText}`,
    });
  }

  const refreshed = (await response.json()) as TokenResponse;

  if (!refreshed.id_token) {
    if (options?.debug) {
      print2(
        "Okta refresh response omitted id_token; falling back to device flow."
      );
    }
    throw refreshError("missing_id_token");
  }

  return mergeRefreshedCredential(identity.credential, refreshed);
};

/**
 * Best-effort revoke of the stored refresh_token at Okta's /oauth2/v1/revoke.
 */
export const revokeOktaRefreshToken = async (
  identity: Identity,
  options?: { debug?: boolean }
): Promise<void> => {
  const refresh_token = identity.credential.refresh_token;
  if (!refresh_token) return;

  const providerDomain = getProviderDomain(identity.org);
  const clientId = getClientId(identity.org);
  if (!providerDomain || !clientId) {
    if (options?.debug) {
      print2(
        "Skipping refresh-token revoke: missing provider domain or client id."
      );
    }
    return;
  }

  try {
    const response = await fetch(`https://${providerDomain}/oauth2/v1/revoke`, {
      method: "POST",
      headers: OIDC_HEADERS,
      body: urlEncode({
        client_id: clientId,
        token: refresh_token,
        token_type_hint: "refresh_token",
      }),
    });
    if (!response.ok && options?.debug) {
      print2(
        `Refresh-token revoke returned ${response.status} ${response.statusText}; proceeding with logout.`
      );
    }
  } catch (e) {
    if (options?.debug) {
      const detail = e instanceof Error ? e.message : String(e);
      print2(
        `Refresh-token revoke failed (${detail}); proceeding with logout.`
      );
    }
  }
};
