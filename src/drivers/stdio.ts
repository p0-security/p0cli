/** Copyright © 2024-present P0 Security 

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/

/** Functions to handle stdio
 *
 * These are essentially wrappers around console.foo, but allow for
 * - Better testing
 * - Later redirection / duplication
 */

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
