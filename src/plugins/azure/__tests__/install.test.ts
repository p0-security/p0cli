/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { checkToolVersion, ensureInstall } from "../../../common/install";
import { print2 } from "../../../drivers/stdio";
import { AzInstall, ensureAzInstall } from "../install";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../common/install", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../common/install")>()),
  ensureInstall: vi.fn(),
  checkToolVersion: vi.fn(),
}));

vi.mock("../../../drivers/stdio", () => ({
  print1: vi.fn(),
  print2: vi.fn(),
}));

const mockEnsureInstall = vi.mocked(ensureInstall);
const mockCheckToolVersion = vi.mocked(checkToolVersion);
const mockPrint2 = vi.mocked(print2);

const EXTENSION_SHOW_COMMAND = ["az", "extension", "show", "--name", "ssh"];

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
  it("succeeds when the Azure CLI and its ssh extension are both installed", async () => {
    mockEnsureInstall.mockResolvedValueOnce(true);
    mockCheckToolVersion.mockResolvedValueOnce('{"name": "ssh"}');

    await expect(ensureAzInstall()).resolves.toBe(true);

    expect(mockCheckToolVersion).toHaveBeenCalledWith(
      "the Azure CLI 'ssh' extension",
      EXTENSION_SHOW_COMMAND,
      undefined
    );
    expect(mockPrint2).not.toHaveBeenCalled();
  });

  it("fails without probing the extension when the Azure CLI is missing", async () => {
    mockEnsureInstall.mockResolvedValueOnce(false);

    await expect(ensureAzInstall()).resolves.toBe(false);

    expect(mockCheckToolVersion).not.toHaveBeenCalled();
  });

  it("prints the extension install instructions when the extension is missing", async () => {
    mockEnsureInstall.mockResolvedValueOnce(true);
    mockCheckToolVersion.mockResolvedValueOnce(undefined);

    await expect(ensureAzInstall()).resolves.toBe(false);

    const output = mockPrint2.mock.calls.map((call) => call[0]).join("\n");
    expect(output).toContain(
      "The Azure CLI 'ssh' extension must be installed on your system to continue."
    );
    expect(output).toContain("az extension add --name ssh");
    expect(output).toContain("az upgrade");
  });

  it("threads debug through to the extension probe", async () => {
    mockEnsureInstall.mockResolvedValueOnce(true);
    mockCheckToolVersion.mockResolvedValueOnce('{"name": "ssh"}');

    await expect(ensureAzInstall(true)).resolves.toBe(true);

    expect(mockCheckToolVersion).toHaveBeenCalledWith(
      "the Azure CLI 'ssh' extension",
      EXTENSION_SHOW_COMMAND,
      true
    );
  });
});
