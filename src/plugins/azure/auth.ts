/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { exec } from "../../util";
import { AzureSshRequest } from "./types";

const SUBSCRIPTION_NOT_FOUND_PATTERN =
  /ERROR: The subscription of '.+' doesn't exist in cloud '.+'.+/;
const FAILED_TO_RESOLVE_TENANT_PATTERN = /Failed to resolve tenant '.+'/;
const LOGIN_ATTEMPT_CANCELLED_PATTERN =
  /WARNING: A web browser has been opened at .+ Please continue the login in the web browser.+/;
export const AUTHORIZATION_FAILED_PATTERN =
  /The client '.+' with object id '.+' does not have authorization to perform action '.+' over scope '.+' or the scope is invalid. If access was recently granted, please refresh your credentials/;
export const USER_NOT_IN_CACHE_PATTERN =
  /Exception in handling client: User '.+' does not exist in MSAL token cache./;
export const CONTACT_SUPPORT_MESSAGE =
  "If the issue persists, please contact support@p0.dev.";
export const NASCENT_ACCESS_GRANT_MESSAGE =
  "If access was recently granted, please try again in a few minutes.";
export const ABORT_AUTHORIZATION_FAILED_MESSAGE = `Your Microsoft Token Cache is out of date. Run 'az account clear' and 'az login' to refresh your credentials. ${CONTACT_SUPPORT_MESSAGE}`;

export const azLoginCommand = (tenantId: string) => ({
  command: "az",
  args: [
    "login",
    "--scope",
    "https://management.core.windows.net//.default",
    "--tenant",
    tenantId,
  ],
});

export const azAccountClearCommand = () => ({
  command: "az",
  args: ["account", "clear"],
});

export const azAccountSetCommand = (subscriptionId: string) => ({
  command: "az",
  args: ["account", "set", "--subscription", subscriptionId],
});

export const azAccountShowUserPrincipalName = () => ({
  command: "az",
  args: ["account", "show", "--query", "user.name", "-o", "tsv"],
});

const performAccountClear = async ({ debug }: { debug?: boolean }) => {
  try {
    const { command: azLogoutExe, args: azLogoutArgs } =
      azAccountClearCommand();
    const logoutResult = await exec(azLogoutExe, azLogoutArgs, { check: true });

    if (debug) {
      print2(logoutResult.stdout);
      print2(logoutResult.stderr);
    }
  } catch (error: any) {
    if (debug) {
      // ignore the error if the user is not logged in.
      print2(`Skipping account clear: ${error.stderr}`);
    }
  }
};

const performLogin = async (
  directoryId: string,
  { debug }: { debug?: boolean }
) => {
  try {
    const { command: azLoginExe, args: azLoginArgs } =
      azLoginCommand(directoryId);
    const loginResult = await exec(azLoginExe, azLoginArgs, { check: true });

    if (debug) {
      print2("Logging in to Azure...");
      print2(loginResult.stdout);
      print2(loginResult.stderr);
    }

    return loginResult.stdout;
  } catch (error: any) {
    if (debug) {
      print2("Failed to log in to Azure...");
      print2(error.stderr);
    }

    if (FAILED_TO_RESOLVE_TENANT_PATTERN.test(error.stderr)) {
      throw `Failed to resolve tenant "${directoryId}". If access was recently granted, please try again in a few minutes. If the issue persists, please contact support@p0.dev.`;
    }

    if (LOGIN_ATTEMPT_CANCELLED_PATTERN.test(error.stderr)) {
      throw "Login attempt cancelled. Please try again.";
    }

    throw error;
  }
};

const performSetAccount = async (
  request: { subscriptionId: string; directoryId: string },
  { debug }: { debug?: boolean }
) => {
  try {
    const { command: azAccountSetExe, args: azAccountSetArgs } =
      azAccountSetCommand(request.subscriptionId);
    const accountSetResult = await exec(azAccountSetExe, azAccountSetArgs, {
      check: true,
    });

    if (debug) {
      print2("Setting active Azure subscription...");
      print2(accountSetResult.stdout);
      print2(accountSetResult.stderr);
    }
  } catch (error: any) {
    if (debug) {
      print2("Failed to set active Azure subscription...");
      print2(error.stderr);
    }

    if (SUBSCRIPTION_NOT_FOUND_PATTERN.test(error.stderr)) {
      await performAccountClear({ debug });
      const output = await performLogin(request.directoryId, { debug });
      if (!output.includes(request.subscriptionId))
        throw `Subscription ${request.subscriptionId} not found. ${NASCENT_ACCESS_GRANT_MESSAGE}`;
      await performSetAccount(request, { debug });
      return;
    }
    throw error;
  }
};

const getUserPrincipalName = async ({ debug }: { debug?: boolean }) => {
  try {
    const { command, args } = azAccountShowUserPrincipalName();
    const accountShowResult = await exec(command, args, { check: true });
    if (debug) {
      print2(`Found account information...`);
      print2(accountShowResult.stdout);
      print2(accountShowResult.stderr);
    }
    return accountShowResult.stdout.trim();
  } catch (error: any) {
    throw `Failed to get the current user name: ${error}.`;
  }
};

/**
 * Attempts to set the Azure subscription for the current ssh session request. If
 * the user is not logged in, this function will attempt to log in.
 */
export const azSetSubscription = async (
  request: AzureSshRequest,
  options: { debug?: boolean; forceLogout?: boolean } = {}
) => {
  const { debug, forceLogout } = options;
  if (debug) print2("Forming Azure connection...");

  // Logging out first ensures that any cached credentials are cleared.
  // https://github.com/Azure/azure-cli/issues/29161
  if (forceLogout) await performAccountClear({ debug });

  await performSetAccount(request, options);

  return await getUserPrincipalName(options);
};
