/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { beforeEarlyExit, exitAfterTasks, runExitTasks } from "../exit-tasks";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Keep process.exit from ending the test run
const mockExit = vi
  .spyOn(process, "exit")
  .mockImplementation(() => undefined as never);

const slowTask = () => {
  const task = vi.fn().mockImplementation(async () => {
    await new Promise((resolve) => setTimeout(resolve, 10));
    task.finished = true;
  }) as ReturnType<typeof vi.fn> & { finished?: boolean };
  return task;
};

describe("exit tasks", () => {
  it("waits for every registered task", async () => {
    const task = slowTask();
    const unregister = beforeEarlyExit(task);

    await runExitTasks();
    unregister();

    expect(task.finished).toBe(true);
  });

  it("runs the remaining tasks when one fails", async () => {
    const task = vi.fn().mockResolvedValue(undefined);
    const unregisterFailing = beforeEarlyExit(async () => {
      throw new Error("boom");
    });
    const unregister = beforeEarlyExit(task);

    await expect(runExitTasks()).resolves.toBeUndefined();
    unregisterFailing();
    unregister();

    expect(task).toHaveBeenCalledOnce();
  });

  it("skips a task that was unregistered", async () => {
    const task = vi.fn().mockResolvedValue(undefined);
    const unregister = beforeEarlyExit(task);
    unregister();

    await runExitTasks();

    expect(task).not.toHaveBeenCalled();
  });
});

describe("exiting early", () => {
  const originalExitCode = process.exitCode;

  beforeEach(() => {
    mockExit.mockClear();
  });

  afterEach(() => {
    process.exitCode = originalExitCode;
  });

  describe.each(["SIGHUP", "SIGQUIT"] as const)("on %s", (signal) => {
    it("is only listened for while a task is registered", () => {
      const before = process.listenerCount(signal);

      const unregisterFirst = beforeEarlyExit(vi.fn());
      const unregisterSecond = beforeEarlyExit(vi.fn());
      expect(process.listenerCount(signal)).toBe(before + 1);

      unregisterFirst();
      expect(process.listenerCount(signal)).toBe(before + 1);

      unregisterSecond();
      expect(process.listenerCount(signal)).toBe(before);
    });

    it("finishes the registered tasks, then exits", async () => {
      const task = slowTask();
      const unregister = beforeEarlyExit(task);
      const listener = process.listeners(signal).at(-1) as () => void;

      listener();
      expect(mockExit).not.toHaveBeenCalled();
      await vi.waitFor(() => expect(mockExit).toHaveBeenCalledOnce());
      unregister();

      expect(task.finished).toBe(true);
    });
  });

  it("exits with the given code once the tasks have finished", async () => {
    const task = slowTask();
    const unregister = beforeEarlyExit(task);

    exitAfterTasks(1);
    expect(mockExit).not.toHaveBeenCalled();
    await vi.waitFor(() => expect(mockExit).toHaveBeenCalledWith(1));
    unregister();

    expect(task.finished).toBe(true);
    expect(process.exitCode).toBe(1);
  });

  it("exits right away when nothing is registered", async () => {
    exitAfterTasks(1);

    await vi.waitFor(() => expect(mockExit).toHaveBeenCalledWith(1));
  });
});
