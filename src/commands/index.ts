/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import Sentry from "../common/sentry";
import { print2 } from "../drivers/stdio";
import { checkVersion } from "../middlewares/version";
import { allowCommand } from "./allow";
import { awsCommand } from "./aws";
import { grantCommand } from "./grant";
import { kubeconfigCommand } from "./kubeconfig";
import { loginCommand } from "./login";
import { lsCommand } from "./ls";
import { requestCommand } from "./request";
import { scpCommand } from "./scp";
import { sshCommand } from "./ssh";
import { sys } from "typescript";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

const commands = [
  awsCommand,
  grantCommand,
  loginCommand,
  lsCommand,
  requestCommand,
  allowCommand,
  sshCommand,
  scpCommand,
  kubeconfigCommand,
];

export const cli = commands
  .reduce((m, c) => c(m), yargs(hideBin(process.argv)))
  .middleware(checkVersion)
  .strict()
  .demandCommand(1)
  .fail((message, error, yargs) => {
    if (error) {
      // TODO: Convert expected errors to a subtype of Error
      if (typeof error === "string") {
        print2(error);
      } else {
        const errorId = Sentry.captureException(error);
        const message = unknownErrorMessage(errorId);
        print2(message);
      }
    } else {
      print2(yargs.help());
      print2(`\n${message}`);
    }
    sys.exit(1);
  });

const unknownErrorMessage = (errorId: string) =>
  `P0 encountered an unknown error. Please contact support@p0.dev for assistance. (Error ID ${errorId})`;
