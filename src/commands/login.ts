/** Copyright © 2024-present P0 Security 

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { IDENTITY_FILE_PATH, authenticate } from "../drivers/auth";
import { doc, guard } from "../drivers/firestore";
import { print2 } from "../drivers/stdio";
import { pluginLoginMap } from "../plugins/login";
import { TokenResponse } from "../types/oidc";
import { OrgData } from "../types/org";
import { getDoc } from "firebase/firestore";
import * as fs from "fs/promises";
import * as path from "path";
import yargs from "yargs";

/** Logs in the user
 *
 * Currently only supports login to a single organization. Login credentials, together
 * with organization details, are saved to {@link IDENTITY_FILE_PATH}.
 */
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
