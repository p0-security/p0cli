/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { exec } from "../../util";

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

export const azLogin = async (
  subscriptionId: string,
  options: { debug?: boolean } = {}
) => {
  const { debug } = options;

  if (debug) print2("Logging in to Azure...");

  // Logging out first ensures that any cached credentials are cleared.
  // https://github.com/Azure/azure-cli/issues/29161
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

  const { command: azLoginExe, args: azLoginArgs } = azLoginCommand();
  const loginResult = await exec(azLoginExe, azLoginArgs, { check: true });

  if (debug) {
    print2(loginResult.stdout);
    print2(loginResult.stderr);
    print2(`Setting active Azure subscription to ${subscriptionId}...`);
  }

  const { command: azAccountSetExe, args: azAccountSetArgs } =
    azAccountSetCommand(subscriptionId);
  const accountSetResult = await exec(azAccountSetExe, azAccountSetArgs, {
    check: true,
  });

  if (debug) {
    print2(accountSetResult.stdout);
    print2(accountSetResult.stderr);
  }
};
