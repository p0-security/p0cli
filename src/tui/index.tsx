/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Session, loadSession } from "./session.js";
import React from "react";

export type TuiEntryFlow = "menu" | "request";

export type RunTuiArgs = {
  entry: TuiEntryFlow;
  debug?: boolean;
};

export type RunTuiResult = {
  exitCode: number;
};

/**
 * Signals from the TUI to the host loop. The TUI doesn't run any of these
 * itself — it unmounts cleanly, the host runs the external action with
 * the terminal fully released, then re-mounts the TUI.
 */
export type TuiIntent =
  | { exitCode: number; kind: "exit" }
  | { kind: "login"; orgSlug: string }
  | { kind: "logout" };

/** XTerm "use alternate screen buffer" sequence — pushes the current screen
 *  onto a stack and clears the display so the TUI doesn't trample the user's
 *  shell history. Restored on exit. */
const ENTER_ALT_SCREEN = "\x1b[?1049h\x1b[H";
const EXIT_ALT_SCREEN = "\x1b[?1049l";
const HIDE_CURSOR = "\x1b[?25l";
const SHOW_CURSOR = "\x1b[?25h";

/**
 * Mounts Ink once and resolves with the user's next intent. The host
 * loop in `runTui` handles each intent (login, logout, exit) by
 * suspending the TUI, performing the action with the terminal fully
 * released, and then re-mounting with a refreshed session.
 */
const runTuiOnce = async (args: {
  session: Session;
  entry: TuiEntryFlow;
  debug?: boolean;
}): Promise<TuiIntent> => {
  const { render } = await import("ink");
  const { App } = await import("./App.js");

  let restored = false;
  const restoreTerminal = () => {
    if (restored) return;
    restored = true;
    process.stdout.write(SHOW_CURSOR + EXIT_ALT_SCREEN);
  };

  process.on("exit", restoreTerminal);
  process.stdout.write(ENTER_ALT_SCREEN + HIDE_CURSOR);

  return await new Promise<TuiIntent>((resolve) => {
    const instance = render(
      React.createElement(App, {
        session: args.session,
        entry: args.entry,
        debug: args.debug,
        onIntent: (intent: TuiIntent) => {
          instance.unmount();
          restoreTerminal();
          process.removeListener("exit", restoreTerminal);
          resolve(intent);
        },
      }),
      { exitOnCtrlC: false }
    );
  });
};

/**
 * Drives the TUI lifecycle: load a session, mount the TUI, perform
 * whatever external action the user asked for (login, logout, …), then
 * re-mount with a refreshed session. Returns once the user picks
 * "Quit" (intent === "exit").
 */
export const runTui = async (args: RunTuiArgs): Promise<RunTuiResult> => {
  // Lazy import to avoid pulling auth/firestore into yargs-only code paths.
  const { login } = await import("../commands/login.js");
  const { deleteIdentity } = await import("../drivers/auth/index.js");

  let entry = args.entry;
  let session = await loadSession(args.debug);

  for (;;) {
    const intent = await runTuiOnce({ session, entry, debug: args.debug });

    if (intent.kind === "exit") {
      return { exitCode: intent.exitCode };
    }

    // Subsequent re-mounts always land on the main menu.
    entry = "menu";

    if (intent.kind === "login") {
      try {
        await login({ org: intent.orgSlug }, { debug: args.debug });
      } catch (err) {
        // Surface the failure on the next mount via session.message.
        const message = err instanceof Error ? err.message : String(err);
        session = { kind: "logged-out", defaultOrg: intent.orgSlug, message };
        continue;
      }
    } else if (intent.kind === "logout") {
      await deleteIdentity();
    }

    session = await loadSession(args.debug);
  }
};
