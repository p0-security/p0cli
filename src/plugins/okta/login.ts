/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { OIDC_HEADERS } from "../../common/auth/oidc";
import { urlEncode, validateResponse } from "../../common/fetch";
import { deleteIdentity } from "../../drivers/auth";
import { print2 } from "../../drivers/stdio";
import {
  getClientId,
  getProviderDomain,
  getProviderType,
} from "../../types/authUtils";
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

const oktaConfigurationErrors = [
  "The application's assurance requirements are not met by the 'subject_token'.",
  "The target audience app must be configured to allow the client to request a 'web_sso_token'.",
];

/**
 * Exchanges an Okta OIDC SSO token for an Okta app SSO token.
 *
 * Performs OAuth 2.0 Token Exchange (RFC 8693) to convert general-purpose
 * OIDC tokens into an app-specific Web SSO token.
 *
 * @throws Error if Okta session has expired or been terminated
 */
const fetchSsoWebToken = async (
  appId: string,
  { org, credential }: Identity,
  debug?: boolean
) => {
  const providerType = getProviderType(org);
  const providerDomain = getProviderDomain(org);
  const clientId = getClientId(org);

  if (providerType !== "okta" || !providerDomain || !clientId) {
    throw "Invalid provider configuration for Okta token exchange";
  }

  const init = {
    method: "POST",
    headers: OIDC_HEADERS,
    body: urlEncode({
      audience: `urn:okta:apps:${appId}`,
      client_id: clientId,
      actor_token: credential.access_token,
      actor_token_type: ACCESS_TOKEN_TYPE,
      subject_token: credential.id_token,
      subject_token_type: ID_TOKEN_TYPE,
      grant_type: TOKEN_EXCHANGE_TYPE,
      requested_token_type: WEB_SSO_TOKEN_TYPE,
    }),
  };
  validateProviderDomain(org);
  const response = await fetch(`https:${providerDomain}/oauth2/v1/token`, init);

  if (!response.ok) {
    if (response.status === 400) {
      const data = await response.json();
      if (data.error === "invalid_grant") {
        await deleteIdentity();
        // Check for specific configuration errors so that they aren't conflated with session/token expiry errors.
        if (oktaConfigurationErrors.includes(data.error_description)) {
          print2(
            "Invalid provider configuration - unable to perform token exchange; please fix your configuration, \
            then log out of Okta in your browser and re-execute the p0 command again to reauthenticate."
          );
          if (debug) {
            print2("Fetch SSO Web Token Error Information: " + data);
          }
          throw data.error_description;
        } else {
          throw "Your Okta session has expired. Please log out of Okta in your browser, and re-execute your p0 command to reauthenticate.";
        }
      }
    }

    // Throw a friendly error message if response is invalid
    await validateResponse(response);
  }

  return (await response.json()) as TokenResponse;
};

/** Retrieves an Okta app's SAML response */
const fetchSamlResponse = async (
  org: OrgData,
  { access_token }: TokenResponse
) => {
  const providerType = getProviderType(org);
  const providerDomain = getProviderDomain(org);

  if (providerType !== "okta" || !providerDomain) {
    throw "Invalid provider configuration for Okta SAML response";
  }

  const init = {
    method: "GET",
    headers: omit(OIDC_HEADERS, "Content-Type"),
  };
  validateProviderDomain(org);
  const url = `https://${providerDomain}/login/token/sso?token=${encodeURIComponent(access_token)}`;
  const response = await fetch(url, init);
  await validateResponse(response);
  const html = await response.text();
  const $ = cheerio.load(html);
  const samlInputValue = $('input[name="SAMLResponse"]').val();
  return typeof samlInputValue === "string" ? samlInputValue : undefined;
};

/** Logs in to Okta via OIDC */
export const oktaLogin = async (org: OrgData) =>
  oidcLogin<AuthorizeResponse, TokenResponse>(
    oidcLoginSteps(org, "openid email profile okta.apps.sso", () => {
      const providerType = getProviderType(org);
      const providerDomain = getProviderDomain(org);

      if (providerType !== "okta" || !providerDomain) {
        throw `Invalid provider configuration (expected okta OIDC provider)`;
      }
      return {
        deviceAuthorizationUrl: `https://${providerDomain}/oauth2/v1/device/authorize`,
        tokenUrl: `https://${providerDomain}/oauth2/v1/token`,
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
  config: AwsFederatedLogin,
  debug?: boolean
): Promise<string> => {
  const webTokenResponse = await fetchSsoWebToken(
    config.provider.appId,
    identity,
    debug
  );
  const samlResponse = await fetchSamlResponse(identity.org, webTokenResponse);
  if (!samlResponse) {
    throw "No SAML assertion obtained from Okta.";
  }
  return samlResponse;
};
