/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { withRedirectServer } from "../common/auth/server";
import { fetchTokenRequest } from "../drivers/api";
import { authenticate } from "../drivers/auth/index";
import { print2 } from "../drivers/stdio";
import { Authn } from "../types/identity";
import open from "open";
import pkceChallenge from "pkce-challenge";
import { sys } from "typescript";
import yargs from "yargs";

const SLACK_REDIRECT_PORT = 52702;
const SLACK_REDIRECT_URL = `http://127.0.0.1:${SLACK_REDIRECT_PORT}`;
const PKCE_LENGTH = 128;
/**
 *    data.code = code;
      data.grant_type = "authorization_code";
 */

type TokenRequest = {
  grant_type: "authorization_code";
  integration: string;
  code: string;
  client_id: string;
  redirect_uri: string;
};

type CodeExchange = {
  code: string;
};

export type TokenResponse = {
  access_token: string;
  id_token: string;
  token_type?: string;
  scope?: string;
  expires_in: number;
  refresh_token?: string;
  device_secret?: string;
  expiry: string;
};

const allowed = ["slack"];

const installArgs = <T>(yargs: yargs.Argv<T>) =>
  yargs.option("component", {
    string: true,
  });
const clientId = "CLIENT_ID";

const requestAuth = async () => {
  const pkce = await pkceChallenge(PKCE_LENGTH);
  const authUrl = "https://slack.com/oauth/v2/authorize";

  const url = `${authUrl}?client_id=${encodeURIComponent(
    clientId
  )}&scope=channels:join,channels:read,chat:write,commands,im:read,im:write,incoming-webhook,usergroups:read,usergroups:write,users:read,users:read.email&state=${encodeURIComponent(
    pkce.code_challenge
  )}&redirect_uri=${encodeURIComponent(SLACK_REDIRECT_URL)}`;

  print2(`Your browser has been opened to visit:

    ${url}\n`);

  open(url).catch(() => {
    print2(`Please visit the following URL to continue login:

    ${url}`);
  });

  return pkce;
};

const writeToken =
  (authn: Authn) =>
  async (
    token: string,
    _args: {
      code_verifier: string;
      code_challenge: string;
    }
  ) => {
    //console.log("Result", token);
    await fetchTokenRequest<TokenRequest>(authn, {
      integration: "slack",
      code: token,
      grant_type: "authorization_code",
      client_id: clientId,
      redirect_uri: SLACK_REDIRECT_URL,
    });
    //console.log("final", result);
    return {};
  };

const install = async (
  args: yargs.ArgumentsCamelCase<{
    component: string;
  }>,
  authn?: Authn
): Promise<undefined | void> => {
  const { component } = args;
  if (!allowed.includes(component)) {
    print2(`${component} install not supported`);
    sys.exit(1);
  }
  const resolvedAuthn = authn ?? (await authenticate());
  await withRedirectServer<any, CodeExchange, object>(
    async () => await requestAuth(),
    async (pkce, token) => await writeToken(resolvedAuthn)(token.code, pkce),
    { port: SLACK_REDIRECT_PORT }
  );
};

export const installCommand = (yargs: yargs.Argv) =>
  yargs.command<{ component: string }>(
    "install component",
    "install components like slack",
    installArgs,
    async (args) => {
      await install(args);
    }
  );
