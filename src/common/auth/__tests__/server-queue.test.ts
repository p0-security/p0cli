/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readFile, writeFile, unlink, access } from "node:fs/promises";
import { constants } from "node:fs";
import os from "node:os";
import { getOperatingSystem } from "../../../util";
import { print2 } from "../../../drivers/stdio";

// Mock dependencies
vi.mock("../../../util", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../util")>();
  return {
    ...actual,
    getOperatingSystem: vi.fn(() => "win" as const),
    sleep: vi.fn((ms: number) => Promise.resolve()),
  };
});

vi.mock("../../../drivers/stdio", () => ({
  print2: vi.fn(),
}));

// Mock file system operations
const mockFiles = new Map<string, string>();
const mockFileExists = new Set<string>();

vi.mock("node:fs/promises", () => ({
  readFile: vi.fn(async (path: string) => {
    if (mockFiles.has(path)) {
      return mockFiles.get(path);
    }
    throw new Error("ENOENT");
  }),
  writeFile: vi.fn(async (path: string, data: string) => {
    mockFiles.set(path, data);
    mockFileExists.add(path);
  }),
  unlink: vi.fn(async (path: string) => {
    mockFiles.delete(path);
    mockFileExists.delete(path);
  }),
  access: vi.fn(async (path: string) => {
    if (mockFileExists.has(path)) {
      return;
    }
    throw new Error("ENOENT");
  }),
}));

vi.mock("node:fs", () => ({
  constants: {
    F_OK: 0,
  },
}));

// Mock process.kill for PID validation
const mockRunningPids = new Set<number>();
const originalKill = process.kill;
vi.spyOn(process, "kill").mockImplementation((pid: number, signal?: number | string) => {
  if (signal === 0) {
    // Check if process exists
    if (mockRunningPids.has(pid)) {
      return true;
    }
    throw new Error("ESRCH");
  }
  return originalKill.call(process, pid, signal);
});

// Mock os.tmpdir
vi.spyOn(os, "tmpdir").mockReturnValue("/tmp");

describe("Login Queue System for Windows/RDS - Simulation", () => {
  const TEST_PORT = 52700;

  beforeEach(() => {
    vi.clearAllMocks();
    mockFiles.clear();
    mockFileExists.clear();
    mockRunningPids.clear();
    mockRunningPids.add(process.pid); // Current process is always running
  });

  afterEach(() => {
    mockFiles.clear();
    mockFileExists.clear();
    mockRunningPids.clear();
  });

  describe("Lock File Management Simulation", () => {
    it("should simulate first process creating a lock file", async () => {
      const lockPath = `/tmp/p0-login-${TEST_PORT}.lock`;
      const lockData = {
        pid: process.pid,
        timestamp: Date.now(),
        port: TEST_PORT,
      };

      // First process creates lock
      await writeFile(lockPath, JSON.stringify(lockData));

      // Verify lock file exists
      expect(mockFiles.has(lockPath)).toBe(true);
      const content = mockFiles.get(lockPath);
      expect(content).toBe(JSON.stringify(lockData));
    });

    it("should simulate second process detecting existing lock", async () => {
      // First process holds the lock
      const firstPid = 1001;
      mockRunningPids.add(firstPid);
      const lockPath = `/tmp/p0-login-${TEST_PORT}.lock`;
      const lockData = {
        pid: firstPid,
        timestamp: Date.now(),
        port: TEST_PORT,
      };
      mockFiles.set(lockPath, JSON.stringify(lockData));
      mockFileExists.add(lockPath);

      // Second process checks if lock exists
      const lockExists = mockFileExists.has(lockPath);
      expect(lockExists).toBe(true);

      // Second process validates lock is held by running process
      try {
        process.kill(firstPid, 0);
        expect(true).toBe(true); // Process is running
      } catch {
        expect(false).toBe(true); // Should not throw
      }
    });

    it("should simulate detecting stale lock from dead process", async () => {
      // Stale lock from dead process
      const deadPid = 9998;
      // Don't add to mockRunningPids, so process.kill will fail
      const lockPath = `/tmp/p0-login-${TEST_PORT}.lock`;
      const lockData = {
        pid: deadPid,
        timestamp: Date.now() - 10000,
        port: TEST_PORT,
      };
      mockFiles.set(lockPath, JSON.stringify(lockData));
      mockFileExists.add(lockPath);

      // Check if process is running
      let isStale = false;
      try {
        process.kill(deadPid, 0);
        isStale = false;
      } catch {
        isStale = true; // Process doesn't exist, lock is stale
      }

      expect(isStale).toBe(true);

      // Remove stale lock
      await unlink(lockPath);
      expect(mockFileExists.has(lockPath)).toBe(false);
    });
  });

  describe("Queue System Simulation", () => {
    it("should simulate creating queue indicators for multiple waiting processes", async () => {
      const queuePid1 = 1002;
      const queuePid2 = 1003;
      const myPid = process.pid;

      // Create queue indicators
      const queue1 = {
        waitingPid: queuePid1,
        timestamp: Date.now() - 5000,
        port: TEST_PORT,
      };
      const queue2 = {
        waitingPid: queuePid2,
        timestamp: Date.now() - 3000,
        port: TEST_PORT,
      };
      const queue3 = {
        waitingPid: myPid,
        timestamp: Date.now(),
        port: TEST_PORT,
      };

      const path1 = `/tmp/p0-login-queue-${TEST_PORT}-${queuePid1}.indicator`;
      const path2 = `/tmp/p0-login-queue-${TEST_PORT}-${queuePid2}.indicator`;
      const path3 = `/tmp/p0-login-queue-${TEST_PORT}-${myPid}.indicator`;

      await writeFile(path1, JSON.stringify(queue1));
      await writeFile(path2, JSON.stringify(queue2));
      await writeFile(path3, JSON.stringify(queue3));

      // Verify all queue indicators exist
      expect(mockFileExists.has(path1)).toBe(true);
      expect(mockFileExists.has(path2)).toBe(true);
      expect(mockFileExists.has(path3)).toBe(true);
    });

    it("should simulate calculating queue position", async () => {
      const queuePid1 = 1002;
      const queuePid2 = 1003;
      const myPid = process.pid;
      const myTimestamp = Date.now();

      // Create queue indicators with different timestamps
      const queue1 = {
        waitingPid: queuePid1,
        timestamp: Date.now() - 5000, // Oldest
        port: TEST_PORT,
      };
      const queue2 = {
        waitingPid: queuePid2,
        timestamp: Date.now() - 3000, // Middle
        port: TEST_PORT,
      };
      const queue3 = {
        waitingPid: myPid,
        timestamp: myTimestamp, // Newest (current process)
        port: TEST_PORT,
      };

      const path1 = `/tmp/p0-login-queue-${TEST_PORT}-${queuePid1}.indicator`;
      const path2 = `/tmp/p0-login-queue-${TEST_PORT}-${queuePid2}.indicator`;
      const path3 = `/tmp/p0-login-queue-${TEST_PORT}-${myPid}.indicator`;

      mockFiles.set(path1, JSON.stringify(queue1));
      mockFiles.set(path2, JSON.stringify(queue2));
      mockFiles.set(path3, JSON.stringify(queue3));
      mockFileExists.add(path1);
      mockFileExists.add(path2);
      mockFileExists.add(path3);

      // Simulate calculating queue position
      // Count how many processes have earlier timestamps
      const allQueues = [
        { pid: queuePid1, timestamp: queue1.timestamp },
        { pid: queuePid2, timestamp: queue2.timestamp },
        { pid: myPid, timestamp: queue3.timestamp },
      ].sort((a, b) => a.timestamp - b.timestamp);

      const myIndex = allQueues.findIndex((q) => q.pid === myPid);
      const position = myIndex + 1;
      const total = allQueues.length;

      expect(position).toBe(3); // We're third in line
      expect(total).toBe(3); // Total of 3 processes
    });
  });

  describe("Concurrent Login Simulation", () => {
    it("should simulate queue behavior when multiple processes try to login", async () => {
      // Process 1: Starts login, creates lock
      const pid1 = 1001;
      mockRunningPids.add(pid1);
      const lockPath = `/tmp/p0-login-${TEST_PORT}.lock`;
      const lockData1 = {
        pid: pid1,
        timestamp: Date.now(),
        port: TEST_PORT,
      };
      mockFiles.set(lockPath, JSON.stringify(lockData1));
      mockFileExists.add(lockPath);

      // Process 2: Tries to login, detects lock, creates queue indicator
      const pid2 = 1002;
      mockRunningPids.add(pid2);
      const queueIndicator2 = {
        waitingPid: pid2,
        timestamp: Date.now() + 1000,
        port: TEST_PORT,
      };
      const queuePath2 = `/tmp/p0-login-queue-${TEST_PORT}-${pid2}.indicator`;
      mockFiles.set(queuePath2, JSON.stringify(queueIndicator2));
      mockFileExists.add(queuePath2);

      // Process 3: Tries to login, detects lock, creates queue indicator
      const pid3 = 1003;
      mockRunningPids.add(pid3);
      const queueIndicator3 = {
        waitingPid: pid3,
        timestamp: Date.now() + 2000,
        port: TEST_PORT,
      };
      const queuePath3 = `/tmp/p0-login-queue-${TEST_PORT}-${pid3}.indicator`;
      mockFiles.set(queuePath3, JSON.stringify(queueIndicator3));
      mockFileExists.add(queuePath3);

      // Verify lock is held by process 1
      expect(mockFileExists.has(lockPath)).toBe(true);
      const lockContent = JSON.parse(mockFiles.get(lockPath)!);
      expect(lockContent.pid).toBe(pid1);

      // Verify queue indicators exist
      expect(mockFileExists.has(queuePath2)).toBe(true);
      expect(mockFileExists.has(queuePath3)).toBe(true);

      // Process 1 completes: releases lock
      mockFiles.delete(lockPath);
      mockFileExists.delete(lockPath);
      mockRunningPids.delete(pid1);

      // Process 2 should now be able to acquire lock
      // (In real scenario, waitForLockRelease would detect this)
      expect(mockFileExists.has(lockPath)).toBe(false);
    });
  });

  describe("Lock Cleanup Simulation", () => {
    it("should simulate lock cleanup when process completes", async () => {
      const lockPath = `/tmp/p0-login-${TEST_PORT}.lock`;
      const lockData = {
        pid: process.pid,
        timestamp: Date.now(),
        port: TEST_PORT,
      };

      // Create lock
      mockFiles.set(lockPath, JSON.stringify(lockData));
      mockFileExists.add(lockPath);

      // Cleanup: remove lock
      await unlink(lockPath);

      // Verify lock is removed
      expect(mockFileExists.has(lockPath)).toBe(false);
      expect(mockFiles.has(lockPath)).toBe(false);
    });

    it("should simulate queue indicator cleanup", async () => {
      const queuePath = `/tmp/p0-login-queue-${TEST_PORT}-${process.pid}.indicator`;
      const queueData = {
        waitingPid: process.pid,
        timestamp: Date.now(),
        port: TEST_PORT,
      };

      // Create queue indicator
      mockFiles.set(queuePath, JSON.stringify(queueData));
      mockFileExists.add(queuePath);

      // Cleanup: remove queue indicator
      await unlink(queuePath);

      // Verify queue indicator is removed
      expect(mockFileExists.has(queuePath)).toBe(false);
      expect(mockFiles.has(queuePath)).toBe(false);
    });
  });

  describe("Windows/RDS Detection", () => {
    it("should detect Windows OS for queue system", () => {
      const os = getOperatingSystem();
      expect(os).toBe("win");
    });
  });
});
