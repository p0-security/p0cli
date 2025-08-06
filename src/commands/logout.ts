/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  getIdentityFilePath,
  getIdentityCachePath,
} from "../drivers/auth/path";
import { print2 } from "../drivers/stdio";
import { P0_PATH } from "../util";
import fs from "fs/promises";
import path from "path";
import process from "process";
import yargs from "yargs";

const getConfigFilePath = () =>
  process.env.P0_ORG
    ? path.join(P0_PATH, `config.json-${process.env.P0_ORG}`)
    : path.join(P0_PATH, "config.json");

const safeDelete = async (filePath: string, description: string) => {
  try {
    const stats = await fs.stat(filePath);
    if (stats.isDirectory()) {
      await fs.rm(filePath, { recursive: true, force: true });
    } else {
      await fs.unlink(filePath);
    }
  } catch (error: any) {
    // ENOENT means file doesn't exist, which is fine for logout
    if (error.code !== "ENOENT") {
      print2(
        `Warning: Could not delete ${description} at ${filePath}: ${error.message}`
      );
    }
  }
};

const logout = async (): Promise<void> => {
  print2("Logging out...");

  const identityPath = getIdentityFilePath();
  await safeDelete(identityPath, "identity file");

  const configPath = getConfigFilePath();
  await safeDelete(configPath, "config file");

  const cachePath = getIdentityCachePath();
  await safeDelete(cachePath, "cache");

  print2("Successfully logged out. All authentication data has been cleared.");
};

export const logoutCommand = (yargs: yargs.Argv) =>
  yargs.command(
    "logout",
    "Log out and clear all authentication data",
    {},
    async () => {
      await logout();
    }
  );
