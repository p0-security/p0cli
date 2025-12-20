/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { OIDC_HEADERS } from "../../common/auth/oidc";
import { urlEncode, validateResponse } from "../../common/fetch";
import { deleteIdentity, remainingTokenTime } from "../../drivers/auth";
import { print2 } from "../../drivers/stdio";
import { Identity } from "../../types/identity";
import { AuthorizeResponse, TokenResponse } from "../../types/oidc";
import { OrgData } from "../../types/org";
import { AwsFederatedLogin } from "../aws/types";
import {
  oidcLogin,
  oidcLoginSteps,
  validateProviderDomain,
} from "../oidc/login";
import * as cheerio from "cheerio";
import { omit } from "lodash";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";
const TOKEN_EXCHANGE_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
const WEB_SSO_TOKEN_TYPE = "urn:okta:oauth:token-type:web_sso_token";

/**
 * Exchanges an Okta OIDC SSO token for an Okta app SSO token.
 *
 * Performs OAuth 2.0 Token Exchange (RFC 8693) to convert general-purpose
 * OIDC tokens into an app-specific Web SSO token.
 *
 * @throws Error if Okta session has expired or been terminated
 */
const fetchSsoWebToken = async (appId: string, identity: Identity) => {
  const { org, credential } = identity;

  // Log diagnostic information about token age
  const tokenRemainingSeconds = remainingTokenTime(identity);
  const tokenAgeSeconds = credential.expires_in - tokenRemainingSeconds;

  if (process.env.DEBUG || process.env.P0_DEBUG) {
    print2(`[DEBUG] Attempting Okta token exchange for app ${appId}`);
    print2(
      `[DEBUG] Token age: ${tokenAgeSeconds}s, Remaining: ${tokenRemainingSeconds}s, Total lifetime: ${credential.expires_in}s`
    );
    print2(
      `[DEBUG] Token expires at: ${new Date(credential.expires_at * 1000).toISOString()}`
    );
  }

  const init = {
    method: "POST",
    headers: OIDC_HEADERS,
    body: urlEncode({
      audience: `urn:okta:apps:${appId}`,
      client_id: org.clientId,
      actor_token: credential.access_token,
      actor_token_type: ACCESS_TOKEN_TYPE,
      subject_token: credential.id_token,
      subject_token_type: ID_TOKEN_TYPE,
      grant_type: TOKEN_EXCHANGE_TYPE,
      requested_token_type: WEB_SSO_TOKEN_TYPE,
    }),
  };
  validateProviderDomain(org);
  const response = await fetch(
    `https:${org.providerDomain}/oauth2/v1/token`,
    init
  );

  if (!response.ok) {
    if (response.status === 400) {
      const data = await response.json();
      if (data.error === "invalid_grant") {
        // Log detailed diagnostic information before clearing identity
        print2(`\n[Okta Session Expired Diagnostics]`);
        print2(
          `  Token was ${tokenAgeSeconds} seconds old (${Math.round(tokenAgeSeconds / 60)} minutes)`
        );
        print2(
          `  Token had ${tokenRemainingSeconds} seconds remaining according to local cache`
        );
        print2(
          `  Okta response: ${data.error_description || "No description provided"}`
        );
        print2(`  Raw Okta error response: ${JSON.stringify(data, null, 2)}`);
        print2(`  HTTP Status: ${response.status} ${response.statusText}`);
        print2(
          `  This indicates Okta invalidated the session server-side before local expiry.`
        );
        print2(
          `  Common causes: admin session termination, Okta session policies, logout from another session.\n`
        );

        await deleteIdentity();
        throw "Your Okta session has expired. Please login again.";
      } else {
        // Log other 400 errors for debugging
        print2(`\n[Okta Token Exchange Error]`);
        print2(`  HTTP Status: ${response.status} ${response.statusText}`);
        print2(`  Raw Okta error response: ${JSON.stringify(data, null, 2)}\n`);
      }
    } else {
      // Log non-400 errors
      let errorBody;
      try {
        errorBody = await response.json();
      } catch {
        errorBody = await response.text();
      }
      print2(`\n[Okta Token Exchange Error]`);
      print2(`  HTTP Status: ${response.status} ${response.statusText}`);
      print2(
        `  Raw response: ${typeof errorBody === "string" ? errorBody : JSON.stringify(errorBody, null, 2)}\n`
      );
    }

    // Throw a friendly error message if response is invalid
    await validateResponse(response);
  }

  if (process.env.DEBUG || process.env.P0_DEBUG) {
    print2(`[DEBUG] Successfully exchanged tokens for Web SSO token`);
  }

  return (await response.json()) as TokenResponse;
};

/** Retrieves an Okta app's SAML response */
const fetchSamlResponse = async (
  org: OrgData,
  { access_token }: TokenResponse
) => {
  const init = {
    method: "GET",
    headers: omit(OIDC_HEADERS, "Content-Type"),
  };
  validateProviderDomain(org);
  const url = `https://${
    org.providerDomain
  }/login/token/sso?token=${encodeURIComponent(access_token)}`;

  if (process.env.DEBUG || process.env.P0_DEBUG) {
    print2(`[DEBUG] Fetching SAML response from Okta SSO endpoint`);
    print2(`[DEBUG] URL: ${url.split("?")[0]}?token=<redacted>`);
  }

  const response = await fetch(url, init);
  await validateResponse(response);
  const html = await response.text();
  const $ = cheerio.load(html);
  const samlInputValue = $('input[name="SAMLResponse"]').val();

  if (process.env.DEBUG || process.env.P0_DEBUG) {
    if (typeof samlInputValue === "string") {
      print2(`[DEBUG] Successfully extracted SAML assertion from HTML response`);
      print2(`[DEBUG] SAML assertion length: ${samlInputValue.length} characters`);
    } else {
      print2(`[DEBUG] WARNING: No SAML assertion found in HTML response`);
      print2(`[DEBUG] HTML response length: ${html.length} characters`);
    }
  }

  return typeof samlInputValue === "string" ? samlInputValue : undefined;
};

/** Logs in to Okta via OIDC */
export const oktaLogin = async (org: OrgData) =>
  oidcLogin<AuthorizeResponse, TokenResponse>(
    oidcLoginSteps(org, "openid email profile okta.apps.sso", () => {
      if (org.providerType !== "okta") {
        throw `Invalid provider type ${org.providerType} (expected "okta")`;
      }
      return {
        deviceAuthorizationUrl: `https://${org.providerDomain}/oauth2/v1/device/authorize`,
        tokenUrl: `https://${org.providerDomain}/oauth2/v1/token`,
      };
    })
  );

/**
 * Converts OIDC tokens into a SAML assertion for AWS federated authentication.
 *
 * This function bridges the gap between modern OIDC authentication (used by P0 CLI)
 * and legacy SAML federation (required by AWS IAM). It performs a two-step process:
 *
 * 1. **Token Exchange (OIDC → Web SSO Token)**:
 *    Exchanges the user's general-purpose OIDC tokens (access_token, id_token) for
 *    an app-specific Web SSO token scoped to the Okta AWS integration app.
 *
 * 2. **SAML Extraction (Web SSO Token → SAML Assertion)**:
 *    Uses the Web SSO token to initiate Okta's SSO flow and extracts the base64-encoded
 *    SAML assertion from the resulting HTML response.
 *
 * @param identity - The user's P0 identity containing OIDC tokens from login
 * @param config - AWS federated login configuration with Okta app details
 * @returns Base64-encoded SAML assertion for AWS authentication
 * @throws Error if Okta session has expired or been terminated
 */
// TODO: Inject Okta app
export const fetchSamlAssertionForAws = async (
  identity: Identity,
  config: AwsFederatedLogin
): Promise<string> => {
  if (process.env.DEBUG || process.env.P0_DEBUG) {
    print2(`[DEBUG] Starting SAML assertion fetch for AWS`);
    print2(`[DEBUG] App ID: ${config.provider.appId}`);
    print2(`[DEBUG] Identity Provider: ${config.provider.identityProvider}`);
  }

  const webTokenResponse = await fetchSsoWebToken(
    config.provider.appId,
    identity
  );
  const samlResponse = await fetchSamlResponse(identity.org, webTokenResponse);

  if (!samlResponse) {
    throw "No SAML assertion obtained from Okta.";
  }

  if (process.env.DEBUG || process.env.P0_DEBUG) {
    print2(`[DEBUG] ==================== SAML ASSERTION ====================`);
    print2(`[DEBUG] Base64-encoded SAML Response (length: ${samlResponse.length}):`);
    print2(`[DEBUG] ${samlResponse}`);
    print2(`[DEBUG] `);
    print2(`[DEBUG] Decoded SAML Assertion XML:`);
    try {
      const decodedSaml = Buffer.from(samlResponse, "base64").toString("utf-8");
      print2(`[DEBUG] ${decodedSaml}`);
    } catch (error) {
      print2(`[DEBUG] ERROR: Failed to decode SAML assertion: ${error}`);
    }
    print2(`[DEBUG] =========================================================`);
  }

  return samlResponse;
};
