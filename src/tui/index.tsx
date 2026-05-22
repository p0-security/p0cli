/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Session, loadSession } from "./session.js";
import { WorkflowValues } from "./workflows/types.js";
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
  | { kind: "logout" }
  | { kind: "workflow"; values: WorkflowValues; workflowId: string };

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
  const { runWorkflow } = await import("./workflows/executor.js");
  const { print2 } = await import("../drivers/stdio.js");

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
    } else if (intent.kind === "workflow") {
      // Clear the main screen buffer (including scrollback where the
      // terminal supports `\x1b[3J`) before handing off. Without this,
      // workflow output appears on top of whatever was on the user's
      // shell before they ran `p0 -i` — including any exit text from
      // a previous SSH session on the same TUI run — making the
      // access-check messages hard to spot.
      await clearMainBuffer();
      await printWorkflowPlaceholder(intent.workflowId, intent.values);

      const result = await runWorkflow(
        intent.workflowId,
        intent.values,
        args.debug
      );
      if (!result.ok && result.message) {
        print2(`\nWorkflow failed: ${result.message}`);
      }
      // Pause so the user can see the workflow's terminal output (which
      // is on the main screen buffer) before we switch back to the TUI's
      // alternate buffer. SSH leaves stdin in a non-trivial state, so
      // pressEnterToContinue is defensive about restoring sane defaults.
      await pressEnterToContinue();
    }

    // Refresh the session before re-mounting. Wrapped because a failure
    // here (transient network, Firebase race after SSH) shouldn't kill
    // the TUI — fall back to logged-out and surface a message.
    try {
      session = await loadSession(args.debug);
    } catch (err) {
      session = {
        kind: "logged-out",
        defaultOrg:
          session.kind === "logged-in" ? session.orgSlug : session.defaultOrg,
        message: `Could not reload session: ${
          err instanceof Error ? err.message : String(err)
        }`,
      };
    }
  }
};

/**
 * Wipes the visible screen + scrollback so the workflow's output
 * starts on a blank canvas. `\x1b[2J` clears the visible region,
 * `\x1b[3J` clears the xterm scrollback (no-op on terminals that
 * don't support it), and `\x1b[H` parks the cursor at the top.
 */
const clearMainBuffer = async (): Promise<void> => {
  if (!process.stdout.isTTY) return;
  process.stdout.write("\x1b[2J\x1b[3J\x1b[H");
};

/**
 * Prints a banner so the user has something to look at during the
 * ~second of latency between the form submit and the first network
 * status message from the workflow handler. Otherwise the cleared
 * screen could read as "broken / hung", especially right after an
 * SSH session ends and the user expects continuity.
 */
const printWorkflowPlaceholder = async (
  workflowId: string,
  values: import("./workflows/types.js").WorkflowValues
): Promise<void> => {
  const { findWorkflow } = await import("./workflows/catalog.js");
  const { buildPreview } = await import("./workflows/preview.js");
  const spec = findWorkflow(workflowId);
  if (!spec) return;
  const preview = buildPreview(spec, values);
  // Two-line banner: the command being run + a "requesting access"
  // hint. The handler itself will start streaming its own status
  // messages immediately after this.
  process.stdout.write(`Starting workflow:\n  $ ${preview}\n\n`);
  process.stdout.write("Requesting access through P0…\n");
};

/**
 * Pauses for a single Enter keypress. Resets the post-SSH terminal
 * state (raw mode off, stdin resumed, listeners removed) so the next
 * Ink mount starts from a clean slate.
 */
const pressEnterToContinue = async (): Promise<void> => {
  if (!process.stdin.isTTY) return;

  const stdin = process.stdin;
  const wasRaw = stdin.isRaw;
  try {
    stdin.setRawMode?.(false);
  } catch {
    // Some terminals reject setRawMode after subprocess handoff; safe to ignore.
  }
  // Stale listeners (e.g. from the SSH child's shared stdio) would
  // re-trigger when we resume — strip them.
  stdin.removeAllListeners("data");
  stdin.setEncoding("utf8");

  process.stdout.write("\nPress Enter to return to the menu… ");
  await new Promise<void>((resolve) => {
    const onData = (chunk: Buffer | string) => {
      const s = typeof chunk === "string" ? chunk : chunk.toString("utf8");
      if (s.includes("\n") || s.includes("\r")) {
        stdin.off("data", onData);
        stdin.pause();
        process.stdout.write("\n");
        resolve();
      }
    };
    stdin.resume();
    stdin.on("data", onData);
  });

  // Restore raw mode if a subsequent Ink mount expects it (Ink will
  // re-enable on its own, but this keeps state observable).
  try {
    stdin.setRawMode?.(wasRaw);
  } catch {
    // Ignore.
  }
};
