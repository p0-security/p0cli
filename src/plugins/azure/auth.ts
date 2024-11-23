/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { exec } from "../../util";

export const azLoginCommand = () => ({
  command: "az",
  args: ["login"],
});

export const azAccountSetCommand = (subscriptionId: string) => ({
  command: "az",
  args: ["account", "set", "--subscription", subscriptionId],
});

export const azLogin = async (subscriptionId: string) => {
  const { command: azLoginExe, args: azLoginArgs } = azLoginCommand();
  await exec(azLoginExe, azLoginArgs, { check: true });

  const { command: azAccountSetExe, args: azAccountSetArgs } =
    azAccountSetCommand(subscriptionId);
  await exec(azAccountSetExe, azAccountSetArgs, { check: true });
};