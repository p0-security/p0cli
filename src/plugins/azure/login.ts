/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { OIDC_HEADERS } from "../../common/auth/oidc";
import { withRedirectServer } from "../../common/auth/server";
import { urlEncode, validateResponse } from "../../common/fetch";
import { print2 } from "../../drivers/stdio";
import { AuthorizeRequest, TokenResponse } from "../../types/oidc";
import { OrgData } from "../../types/org";
import open from "open";
import pkceChallenge from "pkce-challenge";

const AZURE_SCOPE = "openid profile email offline_access";
const AZURE_REDIRECT_PORT = 52701;
const PKCE_LENGTH = 128;

type CodeExchange = {
  code: string;
  state: string;
};

const requestAuth = async (org: OrgData, redirectUrl: string) => {
  if (!org.providerDomain) {
    throw "Azure login requires a configured provider domain.";
  }

  const pkce = await pkceChallenge(PKCE_LENGTH);
  const baseUrl = `https://login.microsoftonline.com/${org.providerDomain}/oauth2/v2.0/authorize`;

  const authBody: AuthorizeRequest = {
    client_id: org.clientId,
    code_challenge: pkce.code_challenge,
    code_challenge_method: "S256",
    redirect_uri: redirectUrl,
    response_type: "code",
    scope: AZURE_SCOPE,
    state: "azure_login",
  };

  const url = `${baseUrl}?${urlEncode(authBody)}`;

  print2(`Your browser has been opened to visit:

    ${url}\n`);

  open(url).catch(() => {
    print2(`Please visit the following URL to continue login:

    ${url}`);
  });

  return pkce;
};

const requestToken = async (
  org: OrgData,
  code: string,
  pkce: { code_challenge: string; code_verifier: string },
  redirectUrl: string
) => {
  if (!org.providerDomain) {
    throw "Azure login requires a configured provider domain.";
  }

  const tokenUrl = `https://login.microsoftonline.com/${org.providerDomain}/oauth2/v2.0/token`;

  const body = {
    client_id: org.clientId,
    code,
    code_verifier: pkce.code_verifier,
    grant_type: "authorization_code",
    redirect_uri: redirectUrl,
  };

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      ...OIDC_HEADERS,
      Accept: "application/json",
      Origin: redirectUrl,
    },
    body: urlEncode(body),
  });

  const valid = await validateResponse(response);
  return (await valid.json()) as TokenResponse;
};

export const azureLogin = async (org: OrgData): Promise<TokenResponse> => {
  return await withRedirectServer<any, CodeExchange, TokenResponse>(
    async (_, redirectUrl) => await requestAuth(org, redirectUrl),
    async (pkce, token, redirectUrl) => await requestToken(org, token.code, pkce, redirectUrl),
    { port: AZURE_REDIRECT_PORT }
  );
};
