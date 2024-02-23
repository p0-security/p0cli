/** Copyright © 2024 P0 Security 

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/

/** Waits the specified delay (in ms)
 *
 * The returned promise is cancelable:
 * ```
 * const wait = sleep(10);
 * ...
 * wait.cancel();
 * ```
 */
export const sleep = (timeoutMillis: number) => {
  let timer: NodeJS.Timeout | undefined = undefined;
  const promise = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, timeoutMillis);
  });
  return Object.assign(promise, { cancel: () => clearTimeout(timer) });
};

export const noop = () => {};

export const readLine = () =>
  new Promise<string>((resolve) =>
    process.stdin.on("data", (d) => resolve(d.toString()))
  );
