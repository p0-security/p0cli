/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { beforeSignalExit, runExitTasks } from "../exit-tasks";
import { describe, expect, it, vi } from "vitest";

describe("exit tasks", () => {
  it("waits for every registered task", async () => {
    let finished = false;
    const unregister = beforeSignalExit(async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      finished = true;
    });

    await runExitTasks();
    unregister();

    expect(finished).toBe(true);
  });

  it("runs the remaining tasks when one fails", async () => {
    const task = vi.fn().mockResolvedValue(undefined);
    const unregisterFailing = beforeSignalExit(async () => {
      throw new Error("boom");
    });
    const unregister = beforeSignalExit(task);

    await expect(runExitTasks()).resolves.toBeUndefined();
    unregisterFailing();
    unregister();

    expect(task).toHaveBeenCalledOnce();
  });

  it("skips a task that was unregistered", async () => {
    const task = vi.fn().mockResolvedValue(undefined);
    const unregister = beforeSignalExit(task);
    unregister();

    await runExitTasks();

    expect(task).not.toHaveBeenCalled();
  });
});
