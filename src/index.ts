/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { cli } from "./commands";
import { loadConfig } from "./drivers/config";
import { noop } from "lodash";

export const P0_VERSION = "0.18.1';";

export const main = async () => {
  // Try to load the config early here to get the custom help/contact messages (if any)
  try {
    await loadConfig();
  } catch (error: any) {
    // The config file may not be present if the user has not yet logged in,
    //  or has deleted the config. In that case, ignore the error and continue.
    // It will use the default messages instead.
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }

  // We can suppress output here, as .fail() already print2 errors
  void (cli.parse() as any).catch(noop);
};

if (require.main === module) {
  void main();
}
