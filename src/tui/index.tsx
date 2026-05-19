/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Authn } from "../types/identity.js";
import React from "react";

export type TuiEntryFlow = "menu" | "request";

export type RunTuiArgs = {
  authn: Authn;
  entry: TuiEntryFlow;
  debug?: boolean;
};

export type RunTuiResult = {
  exitCode: number;
};

/** XTerm "use alternate screen buffer" sequence — pushes the current screen
 *  onto a stack and clears the display so the TUI doesn't trample the user's
 *  shell history. Restored on exit. */
const ENTER_ALT_SCREEN = "\x1b[?1049h\x1b[H";
const EXIT_ALT_SCREEN = "\x1b[?1049l";
const HIDE_CURSOR = "\x1b[?25l";
const SHOW_CURSOR = "\x1b[?25h";

/**
 * Mounts the Ink app with the given starting flow and resolves once the user
 * exits (submit, cancel, or ctrl-c). The TUI runs in the alternate screen
 * buffer so the user's prior terminal contents are preserved.
 */
export const runTui = async (args: RunTuiArgs): Promise<RunTuiResult> => {
  // Imported lazily so callers that never enter interactive mode don't pay
  // the cost of loading Ink / React on startup.
  const { render } = await import("ink");
  const { App } = await import("./App.js");

  let restored = false;
  const restoreTerminal = () => {
    if (restored) return;
    restored = true;
    process.stdout.write(SHOW_CURSOR + EXIT_ALT_SCREEN);
  };

  // Defensive cleanup for the path where the process dies before the normal
  // unmount runs (uncaught throw, external SIGTERM). Ink enables stdin raw
  // mode, so Ctrl+C arrives as a keystroke and is handled by App's useInput
  // — it does NOT generate SIGINT. SIGTERM from outside will cause Node's
  // default action of exit, which fires the "exit" event below.
  process.on("exit", restoreTerminal);

  process.stdout.write(ENTER_ALT_SCREEN + HIDE_CURSOR);

  return await new Promise<RunTuiResult>((resolve) => {
    const instance = render(
      React.createElement(App, {
        authn: args.authn,
        entry: args.entry,
        debug: args.debug,
        onExit: (exitCode: number) => {
          instance.unmount();
          restoreTerminal();
          process.removeListener("exit", restoreTerminal);
          resolve({ exitCode });
        },
      }),
      { exitOnCtrlC: false }
    );
  });
};
