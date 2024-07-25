/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { OIDC_HEADERS } from "../../common/auth/oidc";
import { urlEncode, validateResponse } from "../../common/fetch";
import { print2 } from "../../drivers/stdio";
import { AuthorizeResponse, TokenResponse } from "../../types/oidc";
import { OrgData } from "../../types/org";
import { sleep, throwAssertNever } from "../../util";
import { capitalize } from "lodash";
import open from "open";

export const DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

export const validateProviderDomain = (org: OrgData) => {
  if (!org.providerDomain) throw "Login requires a configured provider domain.";
};

/** Executes the first step of a device-authorization grant flow */
// cf. https://developer.okta.com/docs/guides/device-authorization-grant/main/
const authorize = async (org: OrgData, scope: string) => {
  if (org.providerType === undefined) {
    throw "Login requires a configured provider type.";
  }
  const init = {
    method: "POST",
    headers: OIDC_HEADERS,
    body: urlEncode({
      client_id: org.clientId,
      scope,
    }),
  };
  validateProviderDomain(org);
  // This is the "org" authorization server; the okta.apps.* scopes are not
  // available with custom authorization servers
  const url =
    org.providerType === "okta"
      ? `https:${org.providerDomain}/oauth2/v1/device/authorize`
      : org.providerType === "ping"
        ? `https://${org.providerDomain}/${org.environmentId}/as/device_authorization`
        : throwAssertNever(org.providerType);
  const response = await fetch(url, init);
  await validateResponse(response);
  return (await response.json()) as AuthorizeResponse;
};

/** Attempts to fetch this device's OIDC token
 *
 * The authorization may or may not be granted at this stage. If it is not, the
 * authorization server will return "authorization_pending", in which case this
 * function will return undefined.
 */
const fetchOidcToken = async (org: OrgData, authorize: AuthorizeResponse) => {
  if (org.providerType === undefined) {
    throw "Login requires a configured provider type.";
  }
  const init = {
    method: "POST",
    headers: OIDC_HEADERS,
    body: urlEncode({
      client_id: org.clientId,
      device_code: authorize.device_code,
      grant_type: DEVICE_GRANT_TYPE,
    }),
  };
  validateProviderDomain(org);
  const url =
    org.providerType === "okta"
      ? `https:${org.providerDomain}/oauth2/v1/token`
      : org.providerType === "ping"
        ? `https://${org.providerDomain}/${org.environmentId}/as/token`
        : throwAssertNever(org.providerType);
  const response = await fetch(url, init);

  if (!response.ok) {
    if (response.status === 400) {
      const data = await response.json();
      if (data.error === "authorization_pending") return undefined;
    }
    await validateResponse(response);
  }
  return (await response.json()) as TokenResponse;
};

/** Waits until user device authorization is complete
 *
 * Returns the OIDC token after completion.
 */
const waitForActivation = async (
  org: OrgData,
  authorize: AuthorizeResponse
) => {
  const start = Date.now();
  while (Date.now() - start <= authorize.expires_in * 1e3) {
    const response = await fetchOidcToken(org, authorize);
    if (!response) await sleep(authorize.interval * 1e3);
    else return response;
  }
  throw "Expired awaiting in-browser authorization.";
};

/** Logs in to an Identity Provider via OIDC */
export const oidcLogin = async (org: OrgData, scope: string) => {
  if (org.providerType === undefined) {
    throw "Login requires a configured provider type.";
  }
  const authorizeResponse = await authorize(org, scope);
  print2(`Please use the opened browser window to continue your P0 login.
  
When prompted, confirm that ${capitalize(org.providerType)} displays this code:

  ${authorizeResponse.user_code}

Waiting for authorization...
`);
  void open(authorizeResponse.verification_uri_complete);
  const oidcResponse = await waitForActivation(org, authorizeResponse);
  return oidcResponse;
};
