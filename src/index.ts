/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { cli } from "./commands";
import { noop } from "lodash";
import { constants } from "node:os";

// Subscribing to this global abort controller allows handling process termination signals anywhere in the application
export const TERMINATION_CONTROLLER = new AbortController();

const terminationHandler = (code: number) => () => {
  TERMINATION_CONTROLLER.abort(code);
  process.exit(128 + code); // by convention the exit code is the signal code + 128
};

process.on("SIGHUP", terminationHandler(constants.signals.SIGHUP));
process.on("SIGINT", terminationHandler(constants.signals.SIGINT));
process.on("SIGQUIT", terminationHandler(constants.signals.SIGQUIT));
process.on("SIGTERM", terminationHandler(constants.signals.SIGTERM));

export const main = () => {
  // We can suppress output here, as .fail() already print1 errors
  void (cli.parse() as any).catch(noop);
};

if (require.main === module) {
  main();
}
