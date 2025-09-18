/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../drivers/stdio";
import { sleep } from "../util";

type RetryOptions = {
  shouldRetry?: (error: unknown) => boolean;
  retries?: number;
  delayMs?: number;
  multiplier?: number;
  maxDelayMs?: number;
  debug?: boolean;
};

const DEFAULT_OPTIONS: Required<RetryOptions> = {
  shouldRetry: () => true,
  retries: 3,
  delayMs: 1_000,
  // A 0 or negative maxDelayMs means no max
  maxDelayMs: 0,
  multiplier: 1.0,
  debug: false,
};

const optionsWithDefaults = (
  options?: RetryOptions
): Required<RetryOptions> => {
  return { ...DEFAULT_OPTIONS, ...(options || {}) };
};

const optionsForNextRetry = (
  options: Required<RetryOptions>
): Required<RetryOptions> => {
  const { delayMs, maxDelayMs, multiplier } = options;
  const nextDelayMs =
    maxDelayMs > 0
      ? Math.min(delayMs * multiplier, maxDelayMs)
      : delayMs * multiplier;
  return {
    ...options,
    retries: options.retries - 1,
    delayMs: nextDelayMs,
  };
};

/**
 * Retries an operation with a delay between retries
 * @param operation operation to retry
 * @param {RetryOptions} options options of retrying the operation
 * @param {function} options.shouldRetry - function to determine if the operation should be retried based on the error
 * @param {number} options.retries - number of retries
 * @param {number} options.delay - time to wait before retrying
 * @param {number} options.multiplier - multiplier to apply to delay after each retry
 * @param {number} options.maxDelayMs - maximum delay between retries; 0 or negative means no max
 * @param {boolean} options.debug - whether to print debug information
 * @returns result of the operation
 */
export async function retryWithSleep<T>(
  operation: () => Promise<T>,
  options?: RetryOptions
): Promise<T> {
  const retryOptions = optionsWithDefaults(options);
  const { shouldRetry, retries, delayMs, debug } = retryOptions;
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
          optionsForNextRetry(retryOptions)
        );
      }
    }
    throw error;
  }
}

/**
 * Retries generation of values with a delay between retries
 * @param operation operation to retry
 * @param {RetryOptions} options options of retrying the operation
 * @param {function} options.shouldRetry - function to determine if the operation should be retried based on the error
 * @param {number} options.retries - number of retries
 * @param {number} options.delay - time to wait before retrying
 * @param {number} options.multiplier - multiplier to apply to delay after each retry
 * @param {number} options.maxDelayMs - maximum delay between retries; 0 or negative means no max
 * @param {boolean} options.debug - whether to print debug information
 * @yields values from the generator
 */
export async function* regenerateWithSleep<T>(
  generator: () => AsyncGenerator<T, void, unknown>,
  options?: RetryOptions
): AsyncGenerator<T, void, unknown> {
  const retryOptions = optionsWithDefaults(options);
  const { shouldRetry, retries, delayMs, debug } = retryOptions;
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
          optionsForNextRetry(retryOptions)
        );
      }
    }
    throw error;
  }
}
