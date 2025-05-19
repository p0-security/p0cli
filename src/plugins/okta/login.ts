/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { OIDC_HEADERS } from "../../common/auth/oidc";
import { urlEncode, validateResponse } from "../../common/fetch";
import { Identity } from "../../types/identity";
import { AuthorizeResponse, TokenResponse } from "../../types/oidc";
import { OrgData } from "../../types/org";
import { AwsFederatedLogin } from "../aws/types";
import { LoginPlugin, LoginPluginMethods } from "../login";
import {
  oidcLogin,
  oidcLoginSteps,
  oidcTokenRefresh as oidcRenewAccessToken,
  validateProviderDomain,
} from "../oidc/login";
import * as cheerio from "cheerio";
import { omit } from "lodash";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";
const TOKEN_EXCHANGE_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
const WEB_SSO_TOKEN_TYPE = "urn:okta:oauth:token-type:web_sso_token";

const SCOPES = "openid email profile offline_access";

/** Exchanges an Okta OIDC SSO token for an Okta app SSO token */
const fetchSsoWebToken = async (
  appId: string,
  { org, credential }: Identity
) => {
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
  await validateResponse(response);
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
  const response = await fetch(url, init);
  await validateResponse(response);
  const html = await response.text();
  const $ = cheerio.load(html);
  const samlInputValue = $('input[name="SAMLResponse"]').val();
  return typeof samlInputValue === "string" ? samlInputValue : undefined;
};

/** Logs in to Okta via OIDC */
export const oktaLogin: LoginPlugin = async (
  org: OrgData
): Promise<LoginPluginMethods> => {
  if (org.providerType !== "okta") {
    throw `Invalid provider type ${org.providerType} (expected "okta")`;
  }

  const urls = {
    deviceAuthorizationUrl: `https://${org.providerDomain}/oauth2/v1/device/authorize`,
    tokenUrl: `https://${org.providerDomain}/oauth2/v1/token`,
  };

  const loginSteps = oidcLoginSteps(org, SCOPES, () => urls);

  return {
    login: async () =>
      await oidcLogin<AuthorizeResponse, TokenResponse>(loginSteps),
    renewAccessToken: async (refreshToken: string) =>
      await oidcRenewAccessToken<AuthorizeResponse, TokenResponse>(
        loginSteps,
        refreshToken
      ),
  };
};

/** Retrieves a SAML response for an okta app */
// TODO: Inject Okta app
export const getSamlResponse = async (
  identity: Identity,
  config: AwsFederatedLogin
) => {
  const webTokenResponse = await fetchSsoWebToken(
    config.provider.appId,
    identity
  );
  const samlResponse = await fetchSamlResponse(identity.org, webTokenResponse);
  if (!samlResponse) {
    throw "No SAML assertion obtained from Okta.";
  }
  return samlResponse;
};
