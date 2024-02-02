import { validateResponse } from "../common/fetch";
import { IDENTITY_FILE_PATH, authenticate } from "../drivers/auth";
import { doc, guard } from "../drivers/firestore";
import { oktaLogin } from "../plugins/okta/login";
import { sleep } from "../util";
import { getDoc } from "firebase/firestore";
import * as fs from "fs/promises";
import open from "open";
import * as path from "path";
import { sys } from "typescript";
import yargs from "yargs";

// cf. https://www.oauth.com/oauth2-servers/device-flow/

// TODO: Generate at install time
const CLIENT_ID = "p0cli_6e522d700f09981af7814c8b98b021f9";

const GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

const pluginLoginMap = {
  okta: oktaLogin,
};
const isPluginLoginKey = (
  key: string | undefined
): key is keyof typeof pluginLoginMap => !!key && key in pluginLoginMap;

const tokenUrl = (tenantSlug: string) =>
  `http://localhost:8088/o/${tenantSlug}/auth/token`;

const oauthDFGetCode = async (tenantSlug: string) => {
  const params = new URLSearchParams();
  params.append("client_id", CLIENT_ID);
  const response = await fetch(tokenUrl(tenantSlug), {
    method: "POST",
    body: params,
  });
  if (response.status !== 200) {
    throw `could not start login: ${await response.text()}`;
  }
  return (await response.json()) as AuthorizeResponse;
};

const oauthDFGetToken = async (
  tenantSlug: string,
  codeData: AuthorizeResponse
): Promise<object> => {
  const params = new URLSearchParams();
  params.append("client_id", CLIENT_ID);
  params.append("device_code", codeData.device_code);
  params.append("grant_type", GRANT_TYPE);
  const response = await fetch(tokenUrl(tenantSlug), {
    method: "POST",
    body: params,
  });
  switch (response.status) {
    case 200:
      const data = await response.json();
      return data as object;
    case 400:
      const error = ((await response.json()) as TokenErrorResponse).error;
      switch (error) {
        case "slow_down":
        case "authorization_pending":
          await sleep(codeData.interval);
          return oauthDFGetToken(tenantSlug, codeData);
        default:
          throw error;
      }
    default:
      await validateResponse(response);
      return {}; // unreachable;
  }
};

export const login = async (
  args: { org: string },
  options?: { skipAuthenticate?: boolean }
) => {
  try {
    const orgDoc = await getDoc<Omit<OrgData, "slug">, object>(
      doc(`orgs/${args.org}`)
    );
    const orgData = orgDoc.data();
    if (!orgData) {
      console.error("Could not find organization");
      return sys.exit(1);
    }
    const orgWithSlug: OrgData = { ...orgData, slug: args.org };

    const plugin = orgWithSlug?.ssoProvider;
    const loginFn = isPluginLoginKey(plugin)
      ? pluginLoginMap[plugin]
      : genericLogin;
    const tokenResponse = await loginFn(orgWithSlug);
    await writeIdentity(orgWithSlug, tokenResponse);

    // validate auth
    if (!options?.skipAuthenticate) await authenticate();

    console.error(`You are now logged in, and can use the p0 CLI.`);
  } catch (error: any) {
    console.dir(error, { depth: null });
  }
};

const writeIdentity = async (org: OrgData, credential: TokenResponse) => {
  const expires_at = Date.now() * 1e-3 + credential.expires_in - 1; // Add 1 second safety margin
  console.error(`Saving authorization to ${IDENTITY_FILE_PATH}.`);
  const dir = path.dirname(IDENTITY_FILE_PATH);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(
    IDENTITY_FILE_PATH,
    JSON.stringify(
      {
        credential: { ...credential, expires_at },
        org,
      },
      null,
      2
    ),
    {
      mode: "600",
    }
  );
};

const genericLogin = async (org: OrgData) => {
  const codeData = await oauthDFGetCode(org.slug);
  const url = codeData.verification_uri;

  console.error(`Opening a web browser at the following location:

    ${url}

Before authorizing, confirm that this code is displayed:

    ${codeData.user_code}
  `);

  // No need to await the browser process
  void open(url);

  console.error(`Waiting for authorization ...`);

  const tokenData = await oauthDFGetToken(org.slug, codeData);

  console.error(`Authorized.`);

  return tokenData as TokenResponse;
};

export const loginCommand = (yargs: yargs.Argv) =>
  yargs.command<{ org: string }>(
    "login <org>",
    "Log in to p0 using a web browser",
    (yargs) =>
      yargs.positional("org", {
        demandOption: true,
        type: "string",
        describe: "Your P0 organization ID",
      }),
    guard(login)
  );
