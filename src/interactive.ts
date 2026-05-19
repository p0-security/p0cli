/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authenticate } from "./drivers/auth";

/**
 * Authenticates, launches the Ink-based TUI, and translates its result into a
 * process exit code. Lives outside src/tui/ so that callers in CommonJS code
 * (yargs handlers) don't have to deal with the ESM boundary.
 */
export const runInteractive = async (options: {
  entry: "menu" | "request";
  debug?: boolean;
}): Promise<void> => {
  const authn = await authenticate({ debug: options.debug });
  // Dynamic import because src/tui is an ESM sub-package; statically importing
  // from CJS callers fails under Node16 module resolution.
  const { runTui } = await import("./tui/index.js");
  const result = await runTui({
    authn,
    entry: options.entry,
    debug: options.debug,
  });
  if (result.exitCode !== 0) {
    process.exit(result.exitCode);
  }
};
