/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { mcpCommand } from "./mcp";
import yargs from "yargs";

export const claudeCommand = (yargs: yargs.Argv) =>
  yargs.command("claude", "Interact with Claude Code", (yargs) =>
    yargs
      .option("debug", {
        type: "boolean",
        default: false,
        description: "Emit debug logs",
      })
      .demandCommand(1)
      .command("mcp", "Configure Claude MCP servers", mcpCommand)
  );
