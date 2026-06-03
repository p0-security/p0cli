/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { getIdentityFilePath } from "./path";
import lockfile from "proper-lockfile";

// If a lock holder dies without releasing, the lock file's mtime stops
// updating; after STALE_LOCK_MS another process is allowed to steal it.
const STALE_LOCK_MS = 30_000;

// Bound the *total* wait so a hung peer process can't make this CLI invocation
// appear to hang. The retry backoff below sums to ~20s in the worst case, then
// proper-lockfile gives up and we let the caller fall through to device flow.
const LOCK_RETRY_OPTIONS = {
  retries: 8,
  factor: 1.5,
  minTimeout: 100,
  maxTimeout: 4000,
};

/**
 * Serialize critical sections that read-modify-write the identity file.
 *
 * Acquires an exclusive `proper-lockfile` on identity.json (creates an
 * adjacent `.lock` directory) and releases it after `fn` resolves or rejects.
 * The caller is expected to re-read the identity inside `fn` because a peer
 * may have updated it while we were waiting on the lock.
 *
 * Requires identity.json to exist — caller's responsibility.
 */
export const withIdentityLock = async <T>(fn: () => Promise<T>): Promise<T> => {
  const release = await lockfile.lock(getIdentityFilePath(), {
    stale: STALE_LOCK_MS,
    retries: LOCK_RETRY_OPTIONS,
  });
  try {
    return await fn();
  } finally {
    try {
      await release();
    } catch {
      // release() may throw if the lock was stolen (we exceeded stale time)
      // or already released. The on-disk state is still consistent because
      // writeIdentity is atomic; nothing useful to do here.
    }
  }
};
