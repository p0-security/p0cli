import { OIDC_HEADERS } from "../../common/auth/oidc";
import { withRedirectServer } from "../../common/auth/server";
import { urlEncode, validateResponse } from "../../common/fetch";
import { config } from "../../drivers/env";
import { AuthorizeRequest, TokenResponse } from "../../types/oidc";
import open from "open";

type CodeExchange = {
  code: string;
  authuser: string;
};

const GOOGLE_OIDC_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_OIDC_EXCHANGE_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_OIDC_REDIRECT_PORT = 52700;
const GOOGLE_OIDC_REDIRECT_URL = `http://127.0.0.1:${GOOGLE_OIDC_REDIRECT_PORT}`;
const PKCE_LENGTH = 128;

const requestAuth = async () => {
  const pkceChallenge = (await import("pkce-challenge")).default as any;
  const pkce = await pkceChallenge(PKCE_LENGTH);
  const authBody: AuthorizeRequest = {
    client_id: config.google.clientId,
    code_challenge: pkce.code_challenge,
    code_challenge_method: "S256",
    redirect_uri: GOOGLE_OIDC_REDIRECT_URL,
    response_type: "code",
    scope: "openid",
  };
  const url = `${GOOGLE_OIDC_URL}?${urlEncode(authBody)}`;
  open(url).catch(() => {
    console.error(`Please visit the following URL to continue login:

${url}`);
  });
  return pkce;
};

const requestToken = async (
  code: string,
  pkce: { code_challenge: string; code_verifier: string }
) => {
  const body = {
    client_id: config.google.clientId,
    client_secret: config.google.clientSecret,
    code,
    code_verifier: pkce.code_verifier,
    grant_type: "authorization_code",
    redirect_uri: GOOGLE_OIDC_REDIRECT_URL,
  };
  const response = await fetch(GOOGLE_OIDC_EXCHANGE_URL, {
    method: "POST",
    headers: OIDC_HEADERS,
    body: urlEncode(body),
  });
  const valid = await validateResponse(response);
  return (await valid.json()) as TokenResponse;
};

export const googleLogin = async () => {
  return await withRedirectServer<any, CodeExchange, TokenResponse>(
    async () => await requestAuth(),
    async (pkce, token) => await requestToken(token.code, pkce),
    { port: GOOGLE_OIDC_REDIRECT_PORT }
  );
};
