/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { ensureInstall } from "../../../common/install";
import { AzInstall, ensureAzInstall } from "../install";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../common/install", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../common/install")>()),
  ensureInstall: vi.fn(),
}));

const mockEnsureInstall = vi.mocked(ensureInstall);

beforeEach(() => {
  vi.clearAllMocks();
});

describe("AzInstall", () => {
  it("always installs the Azure CLI together with its ssh extension, never alone", () => {
    const commands = AzInstall.az!.commands.darwin;
    expect(commands).toContain("brew install azure-cli");
    expect(commands[commands.length - 1]).toBe("az extension add --name ssh");
  });
});

describe("ensureAzInstall", () => {
  it.each([true, false])(
    "delegates to the shared install flow (result: %s)",
    async (result) => {
      mockEnsureInstall.mockResolvedValueOnce(result);

      await expect(ensureAzInstall()).resolves.toBe(result);

      expect(mockEnsureInstall).toHaveBeenCalledWith(
        expect.arrayContaining(["az"]),
        AzInstall
      );
    }
  );
});
