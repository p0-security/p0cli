/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { withRedirectServer } from "../server";
import http from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Under vitest the landing-page assets resolve to src/public, which does not exist
vi.mock("node:fs/promises", () => ({
  readFile: vi.fn().mockResolvedValue(Buffer.from("")),
}));

vi.mock("../../../util", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../util")>()),
  getAppName: () => "p0",
}));

describe("withRedirectServer", () => {
  let blocker: http.Server;
  let port: number;

  beforeEach(async () => {
    blocker = http.createServer();
    await new Promise<void>((resolve) => blocker.listen(0, resolve));
    const address = blocker.address();
    if (!address || typeof address === "string")
      throw new Error("blocker is not listening on a TCP port");
    port = address.port;
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => blocker.close(() => resolve()));
  });

  it("explains that another login holds the port when the port is in use", async () => {
    const beginAuth = vi.fn();

    await expect(withRedirectServer(beginAuth, vi.fn(), { port })).rejects.toBe(
      `Login failed: port ${port} is already in use, probably by another \`p0 login\` waiting for browser approval.\nFinish or cancel that login (Ctrl+C in its terminal), then run this command again.`
    );
    expect(beginAuth).not.toHaveBeenCalled();
  });
});
