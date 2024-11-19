/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { exec } from "../../util";

const azLogin = async () => {
  await exec("az", ["login"]);
};

export const getAzPrincipal = async (): Promise<string> => {
  // Log in every time we retrieve the principal. Azure role assignments seem to only apply after logging in, so
  // we require a new login each time. We don't strictly need to do it here per se, but it's a good place to do it
  // since we need the principal name to go forward, and this ensures we can get it.
  await azLogin();

  const { code, stdout, stderr } = await exec("az", [
    "ad",
    "signed-in-user",
    "show",
  ]);

  if (code !== 0) {
    print2(stdout);
    print2(stderr);
    throw `Failed to get Azure principal information`;
  }

  const userInfo = JSON.parse(stdout);

  if (!("userPrincipalName" in userInfo) || !userInfo.userPrincipalName) {
    print2(stdout);
    throw `Failed to get Azure principal information: userPrincipalName not found`;
  }

  return userInfo.userPrincipalName;
};
