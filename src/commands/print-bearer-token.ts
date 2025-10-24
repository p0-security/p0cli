/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authenticate } from "../drivers/auth";
import { loadCredentials } from "../drivers/auth";
import { print1 } from "../drivers/stdio";
import yargs from "yargs";

const printBearerTokenArgs = <T>(yargs: yargs.Argv<T>) => yargs.help(false);

export const printBearerTokenCommand = (yargs: yargs.Argv) =>
  yargs
    .command(
      "print-bearer-token",
      false, // hides command from --help output
      printBearerTokenArgs,
      printBearerToken
    )
    .option("debug", {
      type: "boolean",
      describe: "Print debug information.",
    });

export const printBearerToken = async () => {
  //const authn = await authenticate();
  const identity = await loadCredentials();

  const token = identity?.credential?.access_token;
  if (!token) {
    console.error("No access token found in identity.");
    process.exit(1);
  }
  print1(token);
};
