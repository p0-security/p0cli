/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

// Ctrl+C, `kill`, closing the terminal, and Ctrl+\
const EXIT_SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"] as const;

let interceptions = 0;

/** Whether a command is currently handling the exit signals itself */
export const exitSignalsIntercepted = () => interceptions > 0;

/** Runs a command's work so that an exit signal interrupts it, instead of
 * ending the process on the spot.
 *
 * Use this for a command that has things to finish on its way out. While the
 * work runs, a signal aborts `interrupted` and nothing else. The work is
 * expected to stop what it is doing and return, which leaves the command to
 * run through to its usual end.
 */
export const interruptOnExitSignal = async <T>(
  work: (interrupted: AbortSignal) => Promise<T>
): Promise<T> => {
  const controller = new AbortController();
  const onSignal = () => controller.abort();

  for (const signal of EXIT_SIGNALS) {
    process.on(signal, onSignal);
  }
  interceptions++;

  try {
    return await work(controller.signal);
  } finally {
    for (const signal of EXIT_SIGNALS) {
      process.removeListener(signal, onSignal);
    }
    interceptions--;
  }
};
