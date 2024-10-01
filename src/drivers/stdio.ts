/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

/** Functions to handle stdio
 *
 * These are essentially wrappers around console.foo, but allow for
 * - Better testing
 * - Later redirection / duplication
 */
import { sleep } from "../util";
import { mapValues } from "lodash";

/** Used to output machine-readable text to stdout
 *
 * In general this should not be used for text meant to be consumed
 * only by humans.
 */
export function print1(message: any) {
  // eslint-disable-next-line no-console
  console.log(message);
}

/** Output human-consumable text to stderr
 *
 * In general this should not be used for machine-consumed text.
 */
export function print2(message: any) {
  // eslint-disable-next-line no-console
  console.error(message);
}

const AnsiCodes = {
  Reset: "00",
  Dim: "02",
  Green: "32",
  Yellow: "33",
} as const;

const Ansi = (value: string) => `\u001b[${value}`;

/** Creates an ANSI Select Graphic Rendition code */
export const AnsiSgr = mapValues(AnsiCodes, (v) => Ansi(v + "m"));

/** Resets the terminal cursor to the beginning of the line */
export function reset2() {
  process.stderr.write(Ansi("0G"));
}

/** Clears the current terminal line */
export function clear2() {
  // Replaces text with spaces
  process.stderr.write(Ansi("2K"));
  reset2();
}

const Spin = {
  items: ["⠇", "⠋", "⠙", "⠸", "⠴", "⠦"],
  delayMs: 200,
};

/** Prints a Unicode spinner until a promise resolves */
export const spinUntil = async <T>(message: string, promise: Promise<T>) => {
  let isDone = false;
  let ix = 0;
  void promise.finally(() => (isDone = true)).catch(() => {});
  while (!isDone) {
    await sleep(Spin.delayMs);
    if (isDone) break;
    clear2();
    process.stderr.write(
      AnsiSgr.Green +
        Spin.items[ix % Spin.items.length] +
        " " +
        message +
        AnsiSgr.Reset
    );
    ix++;
  }
  clear2();
  return await promise;
};
