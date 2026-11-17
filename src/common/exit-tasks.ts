/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

type ExitTask = () => Promise<unknown>;

const exitTasks = new Set<ExitTask>();

/** Registers work that must finish before a signal ends the process.
 *
 * A SIGINT or SIGTERM exits the CLI as soon as tracing has shut down, which
 * cuts off anything a command still has in flight. A task registered here is
 * run, and waited for, before that exit.
 *
 * @returns a function that unregisters the task
 */
export const beforeSignalExit = (task: ExitTask) => {
  exitTasks.add(task);
  return () => {
    exitTasks.delete(task);
  };
};

/** Runs every registered task, resolving once all of them have settled */
export const runExitTasks = async () => {
  await Promise.allSettled([...exitTasks].map(async (task) => await task()));
};
