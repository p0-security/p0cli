import { IDENTITY_FILE_PATH, authenticate } from "../drivers/auth";
import { doc, guard } from "../drivers/firestore";
import { print2 } from "../drivers/stdio";
import { googleLogin } from "../plugins/google/login";
import { oktaLogin } from "../plugins/okta/login";
import { TokenResponse } from "../types/oidc";
import { OrgData } from "../types/org";
import { getDoc } from "firebase/firestore";
import * as fs from "fs/promises";
import * as path from "path";
import yargs from "yargs";

const pluginLoginMap: Record<string, (org: OrgData) => Promise<TokenResponse>> =
  {
    google: googleLogin,
    okta: oktaLogin,
    "oidc-pkce": async (org) => await pluginLoginMap[org.providerType!]!(org),
  };

export const login = async (
  args: { org: string },
  options?: { skipAuthenticate?: boolean }
) => {
  const orgDoc = await getDoc<Omit<OrgData, "slug">, object>(
    doc(`orgs/${args.org}`)
  );
  const orgData = orgDoc.data();
  if (!orgData) throw "Could not find organization";

  const orgWithSlug: OrgData = { ...orgData, slug: args.org };

  const plugin = orgWithSlug?.ssoProvider;
  const loginFn = pluginLoginMap[plugin];

  if (!loginFn) throw "Unsupported login for your organization";

  const tokenResponse = await loginFn(orgWithSlug);
  await writeIdentity(orgWithSlug, tokenResponse);

  // validate auth
  if (!options?.skipAuthenticate) await authenticate({ noRefresh: true });

  print2(`You are now logged in, and can use the p0 CLI.`);
};

const writeIdentity = async (org: OrgData, credential: TokenResponse) => {
  const expires_at = Date.now() * 1e-3 + credential.expires_in - 1; // Add 1 second safety margin
  print2(`Saving authorization to ${IDENTITY_FILE_PATH}.`);
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
