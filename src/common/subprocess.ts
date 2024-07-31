/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../drivers/stdio";
import { AgentArgs } from "../plugins/ssh-agent/types";
import { spawn, SpawnOptionsWithoutStdio } from "node:child_process";

/** Spawns a subprocess with given command, args, and options.
 * May write content to its standard input.
 * Stdout and stderr of the subprocess is printed to stderr in debug mode.
 * The returned promise resolves with stdout or rejects with stderr of the subprocess.
 *
 * The captured output is expected to be relatively small.
 * For larger outputs we should implement this with streams. */
export const asyncSpawn = async (
  { debug }: AgentArgs,
  command: string,
  args?: ReadonlyArray<string>,
  options?: SpawnOptionsWithoutStdio,
  writeStdin?: string
) =>
  new Promise<string>((resolve, reject) => {
    const child = spawn(command, args, options);

    // Use streams for larger output
    let stdout = "";
    let stderr = "";

    if (writeStdin) {
      if (!child.stdin) return reject("Child process has no stdin");
      child.stdin.write(writeStdin);
    }

    child.stdout.on("data", (data) => {
      const str = data.toString("utf-8");
      stdout += str;
      if (debug) {
        print2(str);
      }
    });

    child.stderr.on("data", (data) => {
      const str = data.toString("utf-8");
      stderr += str;
      if (debug) {
        print2(data.toString("utf-8"));
      }
    });

    child.on("exit", (code) => {
      if (debug) {
        print2("Process exited with code " + code);
      }
      if (code !== 0) {
        return reject(stderr);
      }
      resolve(stdout);
    });

    if (writeStdin) {
      child.stdin?.end();
    }
  });
