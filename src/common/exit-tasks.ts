/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

type ExitTask = () => Promise<unknown>;

const exitTasks = new Set<ExitTask>();

// Closing the terminal sends SIGHUP, and Ctrl+\ sends SIGQUIT. Both end the
// process on the spot unless something is listening. SIGINT and SIGTERM are
// not listed because tracing already listens for them, and runs the tasks.
const UNHANDLED_EXIT_SIGNALS = ["SIGHUP", "SIGQUIT"] as const;

/** Registers work that must finish before the process exits early.
 *
 * A signal or an uncaught error ends the CLI before a command has run to its
 * end, which cuts off anything the command still has in flight. A task
 * registered here is run, and waited for, before that exit.
 *
 * @returns a function that unregisters the task
 */
export const beforeEarlyExit = (task: ExitTask) => {
  if (exitTasks.size === 0) {
    for (const signal of UNHANDLED_EXIT_SIGNALS) {
      process.on(signal, onUnhandledExitSignal);
    }
  }
  exitTasks.add(task);

  return () => {
    exitTasks.delete(task);
    if (exitTasks.size === 0) {
      for (const signal of UNHANDLED_EXIT_SIGNALS) {
        process.removeListener(signal, onUnhandledExitSignal);
      }
    }
  };
};

// Signal listeners are called with the signal's name, which is not an exit code
const onUnhandledExitSignal = () => exitAfterTasks();

/** Runs every registered task, resolving once all of them have settled */
export const runExitTasks = async () => {
  await Promise.allSettled([...exitTasks].map(async (task) => await task()));
};

/** Exits the process once every registered task has settled
 *
 * @param exitCode the code to exit with; defaults to `process.exitCode`
 */
export const exitAfterTasks = (exitCode?: number) => {
  // Other handlers may exit first, so they need to report the same code
  if (exitCode !== undefined) process.exitCode = exitCode;
  void runExitTasks().finally(() => process.exit(exitCode));
};
