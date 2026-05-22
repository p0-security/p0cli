/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

/**
 * Entry point for the interactive TUI. Does NOT pre-authenticate — the
 * TUI itself handles logged-in / logged-out state, including launching
 * the login flow when needed. This means `p0 -i` works even when the
 * user has no valid credentials yet.
 */
export const runInteractive = async (options: {
  entry: "menu" | "request";
  debug?: boolean;
}): Promise<void> => {
  // Dynamic import because src/tui is an ESM sub-package; statically importing
  // from CJS callers fails under Node16 module resolution.
  const { runTui } = await import("./tui/index.js");
  const result = await runTui({
    entry: options.entry,
    debug: options.debug,
  });
  if (result.exitCode !== 0) {
    process.exit(result.exitCode);
  }
};
