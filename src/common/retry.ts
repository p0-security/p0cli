/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../drivers/stdio";
import { sleep } from "../util";

const DEFAULT_RETRIES = 3;
const DEFAULT_DELAY_MS = 10_000;
const DEFAULT_MULTIPLIER = 1.0;

/**
 * Retries an operation with a delay between retries
 * @param operation operation to retry
 * @param shouldRetry predicate to evaluate on error; will retry only if this is true
 * @param retries number of retries
 * @param delay time to wait before retrying
 * @param multiplier multiplier to apply to delay after each retry
 * @returns
 */
export async function retryWithSleep<T>(
  operation: () => Promise<T>,
  shouldRetry: (error: unknown) => boolean,
  retries = DEFAULT_RETRIES,
  delayMs: number = DEFAULT_DELAY_MS,
  multiplier: number = DEFAULT_MULTIPLIER,
  debug?: boolean
): Promise<T> {
  try {
    return await operation();
  } catch (error: any) {
    if (shouldRetry(error)) {
      if (retries > 0) {
        if (debug) {
          print2(
            `Retry in ${delayMs}ms (remaining attempts: ${retries}). Cause: ${error}`
          );
        }
        await sleep(delayMs);
        return await retryWithSleep(
          operation,
          shouldRetry,
          retries - 1,
          delayMs * multiplier,
          multiplier,
          debug
        );
      }
    }
    throw error;
  }
}

export async function* regenerateWithSleep<T>(
  generator: () => AsyncGenerator<T, void, unknown>,
  shouldRetry: (error: unknown) => boolean,
  retries = DEFAULT_RETRIES,
  delayMs: number = DEFAULT_DELAY_MS,
  multiplier: number = DEFAULT_MULTIPLIER,
  debug?: boolean
): AsyncGenerator<T, void, unknown> {
  try {
    yield* generator();
  } catch (error: any) {
    if (shouldRetry(error)) {
      if (retries > 0) {
        if (debug) {
          print2(
            `Retry in ${delayMs}ms (remaining attempts: ${retries}). Cause: ${error}`
          );
        }
        await sleep(delayMs);
        yield* regenerateWithSleep(
          generator,
          shouldRetry,
          retries - 1,
          delayMs * multiplier,
          multiplier,
          debug
        );
      }
    }
    throw error;
  }
}
