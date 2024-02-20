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
