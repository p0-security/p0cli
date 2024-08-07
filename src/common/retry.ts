/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { sleep } from "../util";

const MAX_RETRIES = 3;
const MAX_RETRY_BACK_OFF_TIME = 10000;

/**
 * Retries an operation with a delay between retries
 * @param operation operation to retry
 * @param shouldRetry predicate to evaluate on error; will retry only if this is true
 * @param retries number of retries
 * @param delay time to wait before retrying
 * @returns
 */
export async function retryWithSleep<T>(
  operation: () => Promise<T>,
  shouldRetry: (error: unknown) => boolean,
  retries = MAX_RETRIES,
  delayMs: number = MAX_RETRY_BACK_OFF_TIME
): Promise<T> {
  try {
    return await operation();
  } catch (error: any) {
    if (shouldRetry(error)) {
      if (retries > 0) {
        await sleep(delayMs);
        return await retryWithSleep(operation, shouldRetry, retries - 1);
      }
    }
    throw error;
  }
}
