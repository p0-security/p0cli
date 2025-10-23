/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print1 } from "../drivers/stdio";
import fs from "fs/promises";
import os from "os";
import path from "path";
import yargs from "yargs";

const printBearerTokenArgs = <T>(yargs: yargs.Argv<T>) => yargs.help(false);

export const printBearerTokenCommand = (yargs: yargs.Argv) =>
  yargs.command(
    "print-bearer-token",
    "Prints bearer token to stdout",
    printBearerTokenArgs,
    printBearerToken
  );

export const printBearerToken = async () => {
  const identityFilePath = path.join(os.homedir(), ".p0", "identity.json");
  try {
    const rawData = await fs.readFile(identityFilePath);
    const identityData = JSON.parse(rawData.toString());
    print1(identityData.credential?.access_token);
  } catch (error: any) {
    if (error?.code == "ENOENT") {
      throw `Missing identity file.`;
    } else {
      throw error;
    }
  }
};
