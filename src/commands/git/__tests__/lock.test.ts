/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { withFileLock } from "../lock";
import { makeTempDir } from "./fixtures";
import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  vi.useRealTimers();
});

describe("withFileLock", () => {
  it("runs one holder at a time", async () => {
    const lockPath = path.join(await makeTempDir(), "lock");
    let running = 0;
    let most = 0;

    await Promise.all(
      Array.from({ length: 5 }, () =>
        withFileLock(lockPath, async () => {
          running += 1;
          most = Math.max(most, running);
          await new Promise((resolve) => setTimeout(resolve, 5));
          running -= 1;
        })
      )
    );

    expect(most).toBe(1);
  });

  it("takes over the lock of a crashed holder", async () => {
    const lockPath = path.join(await makeTempDir(), "lock");
    await fs.mkdir(lockPath);
    const old = new Date(Date.now() - 60_000);
    await fs.utimes(lockPath, old, old);

    await expect(withFileLock(lockPath, async () => "ran")).resolves.toBe(
      "ran"
    );
    await expect(fs.stat(lockPath)).rejects.toThrow();
  });

  it("does not remove a lock that another holder took", async () => {
    const lockPath = path.join(await makeTempDir(), "lock");

    await withFileLock(lockPath, async () => {
      await fs.rm(lockPath, { recursive: true });
      await fs.mkdir(lockPath);
      await fs.writeFile(path.join(lockPath, "owner"), "other");
    });

    await expect(
      fs.readFile(path.join(lockPath, "owner"), "utf-8")
    ).resolves.toBe("other");
  });
});
