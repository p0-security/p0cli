/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  getIdentityFilePath,
  getIdentityCachePath,
  getConfigFilePath,
} from "../drivers/auth/path";
import { print2 } from "../drivers/stdio";
import fs from "fs/promises";
import yargs from "yargs";

const safeDelete = async (
  filePath: string,
  description: string,
  debug: boolean
) => {
  try {
    await fs.rm(filePath, { recursive: true, force: true });
    if (debug) {
      print2(`Deleted ${description}: ${filePath}`);
    }
  } catch (error: any) {
    if (error.code !== "ENOENT") {
      print2(
        `Warning: Could not delete ${description} at ${filePath}: ${error.message}`
      );
    }
  }
};

const logout = async (debug: boolean): Promise<void> => {
  print2("Logging out...");

  const identityPath = getIdentityFilePath();
  await safeDelete(identityPath, "identity file", debug);

  const configPath = getConfigFilePath();
  await safeDelete(configPath, "config file", debug);

  const cachePath = getIdentityCachePath();
  await safeDelete(cachePath, "cache", debug);

  print2("Successfully logged out. All authentication data has been cleared.");
};

export const logoutCommand = (yargs: yargs.Argv) =>
  yargs.command<{ debug?: boolean }>(
    "logout",
    "Log out and clear all authentication data",
    (yargs) =>
      yargs.option("debug", {
        type: "boolean",
        describe: "Print debug information about deleted files",
        default: false,
      }),
    async (argv) => {
      await logout(argv.debug ?? false);
    }
  );
