/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { exec } from "../../util";
import { KnownError } from "./types";

const knownLoginErrors: KnownError[] = [
  {
    pattern:
      /WARNING: A web browser has been opened at .+ Please continue the login in the web browser.+/,
    message: "Login attempt was cancelled. Please try again.",
  },
];

const knownAccountSetErrors: KnownError[] = [
  {
    pattern: /ERROR: The subscription of '.+' doesn't exist in cloud '.+'.+/,
    message: "Failed to set the active Azure subscription. Please try again.",
  },
];

const normalizeAzureCliError = (
  error: any,
  normalizedErrors: KnownError[],
  options: { debug?: boolean }
) => {
  if (options.debug) {
    print2(error);
  }
  for (const { pattern, message } of normalizedErrors) {
    if (pattern.test(error.stderr)) {
      throw message;
    }
  }
  throw error;
};

export const azLoginCommand = () => ({
  command: "az",
  args: ["login"],
});

export const azLogoutCommand = () => ({
  command: "az",
  args: ["logout"],
});

export const azAccountSetCommand = (subscriptionId: string) => ({
  command: "az",
  args: ["account", "set", "--subscription", subscriptionId],
});

export const azAccountShowUserPrincipalName = () => ({
  command: "az",
  args: ["account", "show", "--query", "user.name", "-o", "tsv"],
});

const performLogout = async ({ debug }: { debug?: boolean }) => {
  try {
    const { command: azLogoutExe, args: azLogoutArgs } = azLogoutCommand();
    const logoutResult = await exec(azLogoutExe, azLogoutArgs, { check: true });

    if (debug) {
      print2(logoutResult.stdout);
      print2(logoutResult.stderr);
    }
  } catch (error: any) {
    if (debug) {
      // ignore the error if the user is not logged in.
      print2(`Skipping logout: ${error.stderr}`);
    }
  }
};

const performLogin = async (
  subscriptionId: string,
  { debug }: { debug?: boolean }
) => {
  try {
    const { command: azLoginExe, args: azLoginArgs } = azLoginCommand();
    const loginResult = await exec(azLoginExe, azLoginArgs, { check: true });

    if (debug) {
      print2(loginResult.stdout);
      print2(loginResult.stderr);
      print2(`Setting active Azure subscription to ${subscriptionId}...`);
    }
  } catch (error: any) {
    throw normalizeAzureCliError(error, knownLoginErrors, { debug });
  }
};

const performSetAccount = async (
  subscriptionId: string,
  { debug }: { debug?: boolean }
) => {
  try {
    const { command: azAccountSetExe, args: azAccountSetArgs } =
      azAccountSetCommand(subscriptionId);
    const accountSetResult = await exec(azAccountSetExe, azAccountSetArgs, {
      check: true,
    });

    if (debug) {
      print2(accountSetResult.stdout);
      print2(accountSetResult.stderr);
    }
  } catch (error) {
    throw normalizeAzureCliError(error, knownAccountSetErrors, { debug });
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

export const azLogin = async (
  subscriptionId: string,
  options: { debug?: boolean } = {}
) => {
  const { debug } = options;
  if (debug) print2("Logging in to Azure...");

  // Logging out first ensures that any cached credentials are cleared.
  // https://github.com/Azure/azure-cli/issues/29161
  await performLogout(options);

  await performLogin(subscriptionId, options);

  await performSetAccount(subscriptionId, options);

  return await getUserPrincipalName(options);
};
