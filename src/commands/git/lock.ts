/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { sleep } from "../../util";
import { hasErrorCode } from "./guards";
import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

// A holder runs for at most one token request (10 s). An older lock is from a
// crash.
const STALE_MS = 20_000;
const TIMEOUT_MS = STALE_MS + 10_000;
const RETRY_MS = 25;

const ownerPath = (lockPath: string) => path.join(lockPath, "owner");

async function tryAcquire(lockPath: string, owner: string): Promise<boolean> {
  try {
    await fs.mkdir(lockPath);
  } catch (error) {
    if (hasErrorCode(error, "EEXIST")) return false;
    throw error;
  }
  await fs.writeFile(ownerPath(lockPath), owner);
  return true;
}

async function removeIfStale(lockPath: string): Promise<void> {
  const held = await fs.stat(lockPath).catch(() => undefined);
  if (!held || Date.now() - held.mtimeMs <= STALE_MS) return;
  // Only one waiter can rename the lock, so only one waiter removes it.
  const moved = `${lockPath}.stale-${randomUUID()}`;
  try {
    await fs.rename(lockPath, moved);
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) return;
    throw error;
  }
  await fs.rm(moved, { recursive: true, force: true });
}

async function release(lockPath: string, owner: string): Promise<void> {
  const current = await fs
    .readFile(ownerPath(lockPath), "utf-8")
    .catch(() => undefined);
  if (current === owner)
    await fs.rm(lockPath, { recursive: true, force: true });
}

/** Runs `fn` while this process holds the lock at `lockPath`. Other callers
 * with the same path wait. `fn` must finish within 20 seconds. */
export async function withFileLock<T>(
  lockPath: string,
  fn: () => Promise<T>
): Promise<T> {
  const owner = randomUUID();
  const deadline = Date.now() + TIMEOUT_MS;
  while (!(await tryAcquire(lockPath, owner))) {
    await removeIfStale(lockPath);
    if (Date.now() > deadline) {
      throw `Timed out waiting for the P0 git token lock (${lockPath})`;
    }
    await sleep(RETRY_MS);
  }
  try {
    return await fn();
  } finally {
    await release(lockPath, owner);
  }
}
