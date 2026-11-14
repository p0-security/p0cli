/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { CREDENTIAL_OPERATIONS, gitCredential } from "./credential";
import { gitInstall } from "./install";
import { gitLogin } from "./login";
import { text } from "node:stream/consumers";
import yargs from "yargs";

const serverUrlPositional = <T>(y: yargs.Argv<T>) =>
  y.positional("serverUrl", {
    type: "string",
    describe:
      "The P0 gateway's MCP server URL, e.g. https://<gateway>/mcps/github",
    demandOption: true,
  });

export const gitCommand = (yargs: yargs.Argv) =>
  yargs.command("git", "Use git through the P0 gateway", (y) =>
    y
      .demandCommand(1)
      .command(
        "install <serverUrl>",
        "Print the git config for an agent's environment",
        (y) =>
          serverUrlPositional(y)
            .option("global", {
              type: "boolean",
              default: false,
              describe: "Write the git config to ~/.gitconfig instead",
            })
            .option("json", {
              type: "boolean",
              default: false,
              describe: "Print the variables as JSON",
            }),
        (argv) => gitInstall(argv)
      )
      .command(
        "login <serverUrl>",
        "Log git in for an agent Session with a code from the git_setup tool",
        (y) =>
          serverUrlPositional(y).option("code", {
            type: "string",
            demandOption: true,
            describe: "The Setup code from the git_setup tool",
          }),
        (argv) => gitLogin(argv)
      )
      .command(
        "credential <operation>",
        false, // git runs this as a credential helper
        (y) =>
          y.positional("operation", {
            choices: CREDENTIAL_OPERATIONS,
            demandOption: true,
          }),
        async (argv) => gitCredential(argv.operation, await text(process.stdin))
      )
  );
