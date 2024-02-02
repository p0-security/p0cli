import { urlEncode, validateResponse } from "../../common/fetch";
import { application } from "../../common/mime";
import { Identity } from "../../types/identity";
import { sleep } from "../../util";
import { AwsOktaSamlUidLocation } from "../aws/types";
import { JSDOM } from "jsdom";
import { omit } from "lodash";
import open from "open";

const OIDC_HEADERS = {
  Accept: application.JSON,
  "Content-Type": application.X_WWW_FORM_URLENCODED,
};

const DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";
const TOKEN_EXCHANGE_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
const WEB_SSO_TOKEN_TYPE = "urn:okta:oauth:token-type:web_sso_token";

const validateProviderDomain = (org: OrgData) => {
  if (!org.providerDomain)
    throw "Okta login requires a configured provider domain.";
};

/** Executes the first step of Okta's device-authorization grant flow */
// cf. https://developer.okta.com/docs/guides/device-authorization-grant/main/
const authorize = async (org: OrgData) => {
  const init = {
    method: "POST",
    headers: OIDC_HEADERS,
    body: urlEncode({
      client_id: org.clientId,
      scope: "openid email profile okta.apps.sso okta.apps.read",
    }),
  };
  validateProviderDomain(org);
  // This is the "org" authorization server; the okta.apps.* scopes are not
  // available with custom authorization servers
  const response = await fetch(
    `https:${org.providerDomain}/oauth2/v1/device/authorize`,
    init
  );
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
  const response = await fetch(
    `https:${org.providerDomain}/oauth2/v1/token`,
    init
  );
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
  while (true) {
    if (Date.now() - start > authorize.expires_in * 1e3) {
      throw "Expired awaiting in-browser authorization.";
    }
    const response = await fetchOidcToken(org, authorize);
    if (!response) await sleep(authorize.interval * 1e3);
    else return response;
  }
};

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
  const dom = new JSDOM(html);
  const samlInput = dom.window.document.querySelector(
    'input[name="SAMLResponse"]'
  );
  return (samlInput as HTMLInputElement | undefined)?.value;
};

/** Logs in to Okta via OIDC */
export const oktaLogin = async (org: OrgData) => {
  const authorizeResponse = await authorize(org);
  console.error(`Please use the opened browser window to continue your P0 login.
  
When prompted, confirm that Okta displays this code:

  ${authorizeResponse.user_code}

Waiting for authorization...
`);
  void open(authorizeResponse.verification_uri_complete);
  const oidcResponse = await waitForActivation(org, authorizeResponse);
  return oidcResponse;
};

/** Retrieves a SAML response for an okta app */
// TODO: Inject Okta app
export const getSamlResponse = async (
  identity: Identity,
  config: AwsOktaSamlUidLocation
) => {
  const webTokenResponse = await fetchSsoWebToken(config.appId, identity);
  const samlResponse = await fetchSamlResponse(identity.org, webTokenResponse);
  if (!samlResponse) {
    throw "No SAML assertion obtained from Okta.";
  }
  return samlResponse;
};
