/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { asyncSpawn } from "../../../common/subprocess";
import { spawnWithCleanEnv } from "../../../util";
import { ensureGcloudLogin } from "../auth";
import { EventEmitter } from "node:events";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../common/subprocess", () => ({
  asyncSpawn: vi.fn(),
}));

vi.mock("../../../drivers/stdio", () => ({
  print2: vi.fn(),
}));

// Spread the original so the real osSafeCommand (used by ./util's
// gcloudCommandArgs) keeps working; only stub the interactive spawn.
vi.mock("../../../util", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../util")>()),
  spawnWithCleanEnv: vi.fn(),
}));

const mockAsyncSpawn = vi.mocked(asyncSpawn);
const mockSpawn = vi.mocked(spawnWithCleanEnv);

/** A fake child process that the test drives by emitting `exit`/`error`. */
const fakeChild = () => {
  const child = new EventEmitter();
  mockSpawn.mockReturnValue(child as any);
  return child;
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("ensureGcloudLogin", () => {
  it("skips login when gcloud credentials are valid", async () => {
    mockAsyncSpawn.mockResolvedValue("ya29.an-access-token");

    await expect(ensureGcloudLogin()).resolves.toBe("ya29.an-access-token");

    expect(mockAsyncSpawn).toHaveBeenCalledTimes(1);
    expect(mockSpawn).not.toHaveBeenCalled();
  });

  it("never prints the access token (checks with debug:false even when debug:true)", async () => {
    mockAsyncSpawn.mockResolvedValue("ya29.an-access-token");

    await ensureGcloudLogin({ debug: true });

    expect(mockAsyncSpawn).toHaveBeenCalledWith({ debug: false }, "gcloud", [
      "auth",
      "print-access-token",
    ]);
  });

  it("runs `gcloud auth login` when credentials are invalid, then returns a fresh token, keeping child stdout off our stdout", async () => {
    // First check rejects (not logged in); after login, the token fetch succeeds.
    mockAsyncSpawn
      .mockRejectedValueOnce("(gcloud) not logged in")
      .mockResolvedValue("ya29.fresh-token");
    const child = fakeChild();

    const promise = ensureGcloudLogin({ debug: false });
    await vi.waitFor(() => expect(mockSpawn).toHaveBeenCalled());
    child.emit("exit", 0);

    await expect(promise).resolves.toBe("ya29.fresh-token");

    const [command, args, options] = mockSpawn.mock.calls[0]!;
    expect(command).toBe("gcloud");
    expect(args).toEqual(["auth", "login"]);
    // stdout (index 1) must be routed to our stderr so it cannot corrupt the
    // ssh-proxy data channel on fd 1.
    expect((options as any).stdio[1]).toBe(process.stderr);
  });

  it("rejects with a helpful message when `gcloud auth login` exits non-zero", async () => {
    mockAsyncSpawn.mockRejectedValue("(gcloud) not logged in");
    const child = fakeChild();

    const promise = ensureGcloudLogin();
    await vi.waitFor(() => expect(mockSpawn).toHaveBeenCalled());
    child.emit("exit", 1);

    await expect(promise).rejects.toMatch(/gcloud auth login/);
  });

  it("rejects when `gcloud auth login` fails to spawn", async () => {
    mockAsyncSpawn.mockRejectedValue("(gcloud) not logged in");
    const child = fakeChild();

    const promise = ensureGcloudLogin();
    await vi.waitFor(() => expect(mockSpawn).toHaveBeenCalled());
    child.emit("error", new Error("ENOENT"));

    await expect(promise).rejects.toMatch(/Failed to run 'gcloud auth login'/);
  });
});
