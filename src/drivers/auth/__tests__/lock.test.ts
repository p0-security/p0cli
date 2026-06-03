/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
// Import after the mock so withIdentityLock binds to the mocked path.
import { withIdentityLock } from "../lock";
import * as fs from "fs/promises";
import * as os from "os";
import * as path from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const tmpIdentityPath = path.join(
  os.tmpdir(),
  `p0-lock-test-${process.pid}-${Date.now()}.json`
);

vi.mock("../path", () => ({
  getIdentityFilePath: () => tmpIdentityPath,
}));

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

beforeEach(async () => {
  await fs.writeFile(tmpIdentityPath, "{}", { mode: 0o600 });
});

afterEach(async () => {
  await fs.rm(tmpIdentityPath, { force: true });
  await fs.rm(`${tmpIdentityPath}.lock`, { recursive: true, force: true });
});

describe("withIdentityLock", () => {
  it("serializes concurrent critical sections", async () => {
    const events: string[] = [];

    const work = (name: string) =>
      withIdentityLock(async () => {
        events.push(`${name}:enter`);
        await sleep(50);
        events.push(`${name}:exit`);
      });

    await Promise.all([work("A"), work("B")]);

    // Whichever ran first, its exit must precede the other's entry.
    const order = events.join(",");
    expect(
      order === "A:enter,A:exit,B:enter,B:exit" ||
        order === "B:enter,B:exit,A:enter,A:exit"
    ).toBe(true);
  });

  it("releases the lock when the inner function resolves", async () => {
    await withIdentityLock(async () => "ok");
    // If the lock was not released, the second call would hang on the test
    // timeout. Reaching the assertion is the success criterion.
    const result = await withIdentityLock(async () => "again");
    expect(result).toBe("again");
  });

  it("releases the lock when the inner function rejects", async () => {
    await expect(
      withIdentityLock(async () => {
        throw new Error("boom");
      })
    ).rejects.toThrow("boom");

    const result = await withIdentityLock(async () => "recovered");
    expect(result).toBe("recovered");
  });

  it("propagates the inner function's return value", async () => {
    const result = await withIdentityLock(async () => ({ value: 42 }));
    expect(result).toEqual({ value: 42 });
  });
});
