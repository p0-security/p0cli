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
  jitterFactor?: number;
  debug?: boolean;
};

const DEFAULT_OPTIONS: Required<RetryOptions> = {
  shouldRetry: () => true,
  retries: 3,
  delayMs: 1_000,
  multiplier: 1.0,
  // A 0 or negative maxDelayMs means no max
  maxDelayMs: 0,
  jitterFactor: 0.5,
  debug: false,
};

const optionsWithDefaults = (
  options?: RetryOptions
): Required<RetryOptions> => {
  if (options?.retries && options.retries < 0) {
    if (options.debug) {
      print2(
        `retries must be 0 or a positive integer. Got ${options.retries}. Using default value ${DEFAULT_OPTIONS.retries}`
      );
    }
    delete options.retries;
  }
  if (options?.delayMs && options.delayMs < 0) {
    if (options.debug) {
      print2(
        `delayMs must be 0 or a positive integer. Got ${options.delayMs}. Using default value ${DEFAULT_OPTIONS.delayMs}`
      );
    }
    delete options.delayMs;
  }
  if (options?.multiplier && options.multiplier < 1.0) {
    if (options.debug) {
      print2(
        `multiplier must be 1.0 or a larger number. Got ${options.multiplier}. Using default value ${DEFAULT_OPTIONS.multiplier}`
      );
    }
    delete options.multiplier;
  }
  if (
    options?.jitterFactor &&
    (options.jitterFactor > 1.0 || options.jitterFactor < 0.0)
  ) {
    if (options.debug) {
      print2(
        `jitterFactor must be between 0.0 and 1.0. Got ${options.jitterFactor}. Using default value ${DEFAULT_OPTIONS.jitterFactor}`
      );
    }
    delete options.jitterFactor;
  }
  return { ...DEFAULT_OPTIONS, ...(options || {}) };
};

const addJitter = (delayMs: number, jitterFactor: number): number => {
  return Math.max(
    0, // ensure non-negative
    delayMs * (1 + jitterFactor * (Math.random() * 2 - 1))
  );
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
 * @param {number} options.retries - number of retries; must be 0 or a positive integer
 * @param {number} options.delay - time to wait before retrying; must be 0 or a positive integer
 * @param {number} options.multiplier - multiplier to apply to delay after each retry; must be 1.0 or a larger number
 * @param {number} options.maxDelayMs - maximum delay between retries; 0 or negative means no max
 * @param {number} options.jitterFactor - previous delay is multiplied with a random factor in the range [1 - jitterFactor, 1 + jitterFactor], before `multiplier`; must be between 0.0 and 1.0 (inclusive)
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
      const jitteredMs = addJitter(delayMs, retryOptions.jitterFactor);
      if (retries > 0) {
        if (debug) {
          print2(
            `\nRetry in ${jitteredMs}ms (remaining attempts: ${retries}). Cause: ${error}`
          );
        }
        await sleep(jitteredMs);
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
 * @param generator generator to run
 * @param {RetryOptions} options options of retrying the operation
 * @param {function} options.shouldRetry - function to determine if the operation should be retried based on the error
 * @param {number} options.retries - number of retries; must be 0 or a positive integer
 * @param {number} options.delay - time to wait before retrying; must be 0 or a positive integer
 * @param {number} options.multiplier - multiplier to apply to delay after each retry; must be 1.0 or a larger number
 * @param {number} options.maxDelayMs - maximum delay between retries; 0 or negative means no max
 * @param {number} options.jitterFactor - previous delay is multiplied with a random factor in the range [1 - jitterFactor, 1 + jitterFactor], before `multiplier`; must be between 0.0 and 1.0 (inclusive)
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
        const jitteredMs = addJitter(delayMs, retryOptions.jitterFactor);
        if (debug) {
          print2(
            `\nRetry in ${jitteredMs}ms (remaining attempts: ${retries}). Cause: ${error}`
          );
        }
        await sleep(jitteredMs);
        yield* regenerateWithSleep(
          generator,
          optionsForNextRetry(retryOptions)
        );
      }
    }
    throw error;
  }
}
