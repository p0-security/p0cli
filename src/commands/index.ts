/** Copyright © 2024-present P0 Security

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../drivers/stdio";
import { checkVersion } from "../middlewares/version";
import { awsCommand } from "./aws";
import { loginCommand } from "./login";
import { lsCommand } from "./ls";
import { requestCommand } from "./request";
import { sshCommand } from "./ssh";
import { VERSION } from "lodash";
import { sys } from "typescript";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

const commands = [
  awsCommand,
  loginCommand,
  lsCommand,
  requestCommand,
  sshCommand,
];

export const cli = commands
  .reduce((m, c) => c(m), yargs(hideBin(process.argv)))
  .middleware(checkVersion)
  .strict()
  .version(VERSION)
  .demandCommand(1)
  .fail((message, error, yargs) => {
    if (error) print2(error);
    else {
      print2(yargs.help());
      print2(`\n${message}`);
    }
    sys.exit(1);
  });
