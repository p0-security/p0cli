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

/** Takes over the signals that would otherwise end the process on the spot.
 *
 * Use this for a command that has work to finish on its way out. While the
 * signals are intercepted they no longer exit the process. They abort
 * `interrupted` instead, and the command is expected to stop what it is doing
 * and run through to its usual end.
 *
 * @returns the signal that gets aborted, and a function that hands the exit
 * signals back
 */
export const interceptExitSignals = () => {
  const controller = new AbortController();
  const onSignal = () => controller.abort();

  for (const signal of EXIT_SIGNALS) {
    process.on(signal, onSignal);
  }
  interceptions++;

  const release = () => {
    for (const signal of EXIT_SIGNALS) {
      process.removeListener(signal, onSignal);
    }
    interceptions--;
  };

  return { interrupted: controller.signal, release };
};
