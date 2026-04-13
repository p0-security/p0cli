/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { isNetworkError } from "./util";

// We retry with these delays: 1s, 2s, 4s, 8s, 16s, 30s, 30s, 30s
// for a total of 121s wait time over 8 retries (ignoring jitter)
export const RETRY_OPTIONS = {
  shouldRetry: (error: unknown) =>
    error === "HTTP Error: 429 Too Many Requests" || isNetworkError(error),
  retries: 8,
  delayMs: 1_000,
  multiplier: 2.0,
  maxDelayMs: 30_000,
};
