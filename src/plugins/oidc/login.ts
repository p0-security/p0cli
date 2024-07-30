/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { OIDC_HEADERS } from "../../common/auth/oidc";
import { urlEncode, validateResponse } from "../../common/fetch";
import { print2 } from "../../drivers/stdio";
import { AuthorizeResponse, OidcLoginStepHelpers } from "../../types/oidc";
import { OrgData } from "../../types/org";
import { sleep } from "../../util";
import { capitalize } from "lodash";
import open from "open";

export const DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

export const validateProviderDomain = (org: OrgData) => {
  if (!org.providerDomain) throw "Login requires a configured provider domain.";
};

/** Executes the first step of a device-authorization grant flow */
// cf. https://developer.okta.com/docs/guides/device-authorization-grant/main/
export const authorize = async <T>(
  request: {
    url: string;
    init: RequestInit;
  },
  validateResponse?: (response: Response) => Promise<Response>
) => {
  const { url, init } = request;
  const response = await fetch(url, init);
  await validateResponse?.(response);
  return (await response.json()) as T;
};

/** Attempts to fetch this device's OIDC token
 *
 * The authorization may or may not be granted at this stage. If it is not, the
 * authorization server will return "authorization_pending", in which case this
 * function will return undefined.
 */
export const fetchOidcToken = async <T>(request: {
  url: string;
  init: RequestInit;
}) => {
  const { url, init } = request;
  const response = await fetch(url, init);
  if (!response.ok) {
    if (response.status === 400) {
      const data = await response.json();
      if (data.error === "authorization_pending") return undefined;
    }
    await validateResponse(response);
  }
  return (await response.json()) as T;
};

const providerType: (org: OrgData) => NonNullable<string> = (org) => {
  if (org.providerType === undefined) {
    throw "Login requires a configured provider type.";
  }
  return org.providerType;
};

/** Waits until user device authorization is complete
 *
 * Returns the OIDC token after completion.
 */
export const waitForActivation = async <A, T>(
  authorize: A,
  extractExpiryInterval: (authorize: A) => {
    expires_in: number;
    interval: number;
  }, // Aws implementation differs from standard OIDC response, need function to extract expiry
  tokenRequest: { url: string; init: RequestInit }
) => {
  const start = Date.now();
  const { expires_in, interval } = extractExpiryInterval(authorize);
  while (Date.now() - start <= expires_in * 1e3) {
    const response = await fetchOidcToken<T>(tokenRequest);
    if (!response) await sleep(interval * 1e3);
    else return response;
  }
  throw "Expired awaiting in-browser authorization.";
};

export const oidcLoginSteps = (
  org: OrgData,
  scope: string,
  urls: () => { deviceAuthorizationUrl: string; tokenUrl: string }
) => {
  const { deviceAuthorizationUrl, tokenUrl } = urls();

  const buildOidcAuthorizeRequest = () => {
    if (org.providerType === undefined) {
      throw "Login requires a configured provider type.";
    }

    validateProviderDomain(org);
    // This is the "org" authorization server; the okta.apps.* scopes are not
    // available with custom authorization servers
    return {
      init: {
        method: "POST",
        headers: OIDC_HEADERS,
        body: urlEncode({
          client_id: org.clientId,
          scope,
        }),
      },
      url: deviceAuthorizationUrl,
    };
  };
  const buildOidcTokenRequest = (authorize: AuthorizeResponse) => {
    if (org.providerType === undefined) {
      throw "Login requires a configured provider type.";
    }
    validateProviderDomain(org);

    return {
      url: tokenUrl,
      init: {
        method: "POST",
        headers: OIDC_HEADERS,
        body: urlEncode({
          client_id: org.clientId,
          device_code: authorize.device_code,
          grant_type: DEVICE_GRANT_TYPE,
        }),
      },
    };
  };
  return {
    providerType: providerType(org),
    validateResponse,
    buildAuthorizeRequest: buildOidcAuthorizeRequest,
    buildTokenRequest: buildOidcTokenRequest,
    processAuthzExpiry: (authorize) => ({
      expires_in: authorize.expires_in,
      interval: authorize.interval,
    }),
    processAuthzResponse: (authorize) => ({
      user_code: authorize.user_code,
      verification_uri_complete: authorize.verification_uri_complete,
    }),
  } as OidcLoginStepHelpers<AuthorizeResponse>;
};

/** Logs in to an Identity Provider via OIDC */
export const oidcLogin = async <A, T>(context: OidcLoginStepHelpers<A>) => {
  const {
    providerType,
    buildAuthorizeRequest,
    buildTokenRequest,
    processAuthzExpiry,
    processAuthzResponse,
    validateResponse,
  } = context;
  const deviceAuthorizationResponse = await authorize<A>(
    buildAuthorizeRequest(),
    validateResponse
  );
  const { user_code, verification_uri_complete } = processAuthzResponse(
    deviceAuthorizationResponse
  );
  print2(`Please use the opened browser window to continue your P0 login.

    When prompted, confirm that ${capitalize(providerType)} displays this code:
    
      ${user_code}
    
    Waiting for authorization...
    `);
  void open(verification_uri_complete);
  return await waitForActivation<A, T>(
    deviceAuthorizationResponse,
    processAuthzExpiry,
    buildTokenRequest(deviceAuthorizationResponse)
  );
};
