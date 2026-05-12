/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const P0_PATH = path.join(path.sep, "tmp", "p0-test");

const loadPathModule = async () => {
  vi.resetModules();
  vi.doMock("../../util", async () => ({
    ...(await vi.importActual<typeof import("../../util")>("../../util")),
    P0_PATH,
  }));
  return await import("../auth/path.js");
};

describe("auth paths", () => {
  afterEach(() => {
    delete process.env.P0_ORG;
    vi.doUnmock("../../util");
  });

  it("uses default paths when P0_ORG is not set", async () => {
    const { getConfigFilePath, getIdentityCachePath, getIdentityFilePath } =
      await loadPathModule();

    expect(getIdentityFilePath()).toBe(path.join(P0_PATH, "identity.json"));
    expect(getIdentityCachePath()).toBe(path.join(P0_PATH, "cache"));
    expect(getConfigFilePath()).toBe(path.join(P0_PATH, "config.json"));
  });

  it("preserves legacy org-scoped auth path shapes", async () => {
    process.env.P0_ORG = "acme";
    const { getConfigFilePath, getIdentityCachePath, getIdentityFilePath } =
      await loadPathModule();

    expect(getIdentityFilePath()).toBe(
      path.join(P0_PATH, "identity-acme.json")
    );
    expect(getIdentityCachePath()).toBe(path.join(P0_PATH, "cache-acme"));
    expect(getConfigFilePath()).toBe(path.join(P0_PATH, "config.json-acme"));
  });

  it("adds the org suffix to nested filenames before the extension", async () => {
    process.env.P0_ORG = "acme";
    const { postfixPath } = await loadPathModule();

    expect(postfixPath("claude/mcp-client.json")).toBe(
      path.join(P0_PATH, "claude", "mcp-client-acme.json")
    );
  });
});
