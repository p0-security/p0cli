/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchAccountInfo } from "../drivers/api";
import {
  authenticate,
  deleteIdentity,
  loadCredentials,
  remainingTokenTime,
  writeIdentity,
} from "../drivers/auth";
import { saveConfig } from "../drivers/config";
import { initializeFirebase } from "../drivers/firestore";
import { getOrgData } from "../drivers/org";
import { print2 } from "../drivers/stdio";
import { pluginLoginMap } from "../plugins/login";
import { Authn } from "../types/identity";
import { OrgData } from "../types/org";
import yargs from "yargs";

const MIN_REMAINING_TOKEN_TIME_SECONDS = 5 * 60;

const doActualLogin = async (orgWithSlug: OrgData) => {
  const plugin =
    orgWithSlug?.ssoProvider ??
    (orgWithSlug.usePassword ? "password" : undefined);

  const loginFn = plugin && pluginLoginMap[plugin];

  if (!loginFn) throw "Unsupported login for your organization";

  const tokenResponse = await loginFn(orgWithSlug);

  await writeIdentity(orgWithSlug, tokenResponse);
};

const formatTimeLeft = (seconds: number) => {
  const totalSeconds = Math.max(0, Math.floor(seconds)); // Ensure non-negative and integer
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
  return `${h}h${m}m${s}s`;
};

/** Logs in the user.
 *
 * If the P0_ORG environment variable is set, it is used as the organization name,
 * and the identity file is written to the system temp directory.
 *
 * Otherwise, the identity file is written to the ~/.p0 directory.
 */
export const login = async (
  args: { org?: string; refresh?: boolean },
  options?: { debug?: boolean; skipAuthenticate?: boolean }
) => {
  // Ignore error, as no credentials may yet be present
  const identity = await loadCredentials().catch(() => undefined);

  const tokenTimeRemaining = identity ? remainingTokenTime(identity) : 0;

  let loggedIn = tokenTimeRemaining > MIN_REMAINING_TOKEN_TIME_SECONDS;
  let orgSlug = args.org || process.env.P0_ORG;

  if (!orgSlug) {
    if (identity && loggedIn) {
      // If no org is provided, and the user is logged in, use the one from the identity
      orgSlug = identity.org.slug;

      print2(`You are currently logged in to the ${orgSlug} organization.`);
      print2(
        `The current session expires in ${formatTimeLeft(tokenTimeRemaining)}.`
      );
    } else {
      throw "The P0 organization ID is required. Please provide it as an argument or set the P0_ORG environment variable.";
    }
  } else {
    if (identity && loggedIn) {
      if (orgSlug !== identity.org.slug || args.refresh) {
        // Force login if user is switching organizations or if --refresh argument is provided
        loggedIn = false;
      } else {
        print2(`You are already logged in to the ${orgSlug} organization.`);
        print2(
          `The current session expires in ${formatTimeLeft(tokenTimeRemaining)}.`
        );
      }
    }
  }

  if (!loggedIn) {
    await saveConfig(orgSlug);
  }

  await initializeFirebase();

  const orgData = await getOrgData(orgSlug);

  const orgWithSlug: OrgData = { ...orgData, slug: orgSlug };

  if (!loggedIn) {
    await doActualLogin(orgWithSlug);
  }

  if (!options?.skipAuthenticate) {
    const authn = await authenticate({ debug: options?.debug });
    await validateTenantAccess(authn, options?.debug);
  }

  if (!loggedIn) {
    print2(
      `You are now logged in to the ${orgSlug} organization, and can use the p0 CLI.`
    );
  }
};

export const loginCommand = (yargs: yargs.Argv) =>
  yargs.command<{ org: string }>(
    "login [org]",
    "Log in to p0 using a web browser",
    (yargs) =>
      yargs
        .positional("org", {
          type: "string",
          describe: "Your P0 organization ID",
        })
        .option("refresh", {
          type: "boolean",
          describe: "Force re-authentication",
          default: false,
        })
        .option("debug", {
          type: "boolean",
          describe: "Print debug information.",
        }),

    (
      args: yargs.ArgumentsCamelCase<{
        org: string;
        refresh?: boolean;
        debug?: boolean;
      }>
    ) => login(args, args)
  );

const validateTenantAccess = async (authn: Authn, debug?: boolean) => {
  try {
    await fetchAccountInfo(authn, debug);
    return true;
  } catch (e) {
    await deleteIdentity();
    throw "Could not find organization, logging out.";
  }
};
