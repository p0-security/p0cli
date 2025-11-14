/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { cleanupStaleSshConfigs } from "../ssh-cleanup";
import * as fs from "fs/promises";
import * as path from "path";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../util", () => ({
  P0_PATH: "/tmp/p0-test",
}));

vi.mock("../../../drivers/stdio", () => ({
  print2: vi.fn(),
}));

describe("ssh-cleanup", () => {
  const configsDir = "/tmp/p0-test/ssh/configs";

  const cleanupTestDirectory = async () => {
    try {
      await fs.rm(configsDir, { recursive: true, force: true });
    } catch {
      // Ignore if doesn't exist
    }
  };

  beforeEach(cleanupTestDirectory);
  afterAll(cleanupTestDirectory);

  it("should handle missing configs directory gracefully", async () => {
    // Should not throw when directory doesn't exist
    await expect(cleanupStaleSshConfigs()).resolves.toBeUndefined();
  });

  it("should not throw if directory is empty", async () => {
    await fs.mkdir(configsDir, { recursive: true });

    // Should not throw on empty directory
    await expect(cleanupStaleSshConfigs()).resolves.toBeUndefined();
  });

  it("should only remove files older than 24 hours", async () => {
    await fs.mkdir(configsDir, { recursive: true });

    // Create a fresh file and a stale file
    const freshFile = path.join(configsDir, "fresh.config");
    const staleFile = path.join(configsDir, "stale.config");

    await fs.writeFile(freshFile, "fresh content");
    await fs.writeFile(staleFile, "stale content");

    // Make stale file 25 hours old
    const staleTime = new Date(Date.now() - 25 * 60 * 60 * 1000);
    await fs.utimes(staleFile, staleTime, staleTime);

    await cleanupStaleSshConfigs();

    // Fresh file should still exist
    await expect(fs.access(freshFile)).resolves.toBeUndefined();

    // Stale file should be removed
    await expect(fs.access(staleFile)).rejects.toThrow();
  });
});
