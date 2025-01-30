/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authenticate, writeIdentity } from "../drivers/auth";
import { saveConfig } from "../drivers/config";
import { fsShutdownGuard, initializeFirebase } from "../drivers/firestore";
import { doc } from "../drivers/firestore";
import { print2 } from "../drivers/stdio";
import { pluginLoginMap } from "../plugins/login";
import { OrgData, RawOrgData } from "../types/org";
import { getDoc } from "firebase/firestore";
import yargs from "yargs";

/** Logs in the user
 *
 * Each terminal window requires a separate login. Login credentials,
 * together with organization details, are saved to /tmp/p0.
 */
export const login = async (
  args: { org: string },
  options?: { skipAuthenticate?: boolean }
) => {
  await saveConfig(args.org);
  await initializeFirebase();

  const orgDoc = await getDoc<RawOrgData, object>(doc(`orgs/${args.org}`));
  const orgData = orgDoc.data();

  if (!orgData) throw "Could not find organization";

  const orgWithSlug: OrgData = { ...orgData, slug: args.org };

  const plugin = orgWithSlug?.ssoProvider;
  const loginFn = pluginLoginMap[plugin];

  if (!loginFn) throw "Unsupported login for your organization";

  const tokenResponse = await loginFn(orgWithSlug);

  await writeIdentity(orgWithSlug, tokenResponse);

  // validate auth
  if (!options?.skipAuthenticate) {
    await authenticate();
  }

  print2(`You are now logged in, and can use the p0 CLI.`);
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
    fsShutdownGuard(login)
  );
