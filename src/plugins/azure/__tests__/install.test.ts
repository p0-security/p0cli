/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { ensureInstall } from "../../../common/install";
import { exec } from "../../../util";
import { AzInstall, ensureAzInstall } from "../install";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Spread the original so the real install metadata keeps working; only stub
// the shared install flow, which has its own tests.
vi.mock("../../../common/install", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../common/install")>()),
  ensureInstall: vi.fn(),
}));

// Spread the original so the real osSafeCommand keeps working; only stub the
// subprocess execution.
vi.mock("../../../util", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../util")>()),
  exec: vi.fn(),
}));

const mockEnsureInstall = vi.mocked(ensureInstall);
const mockExec = vi.mocked(exec);

const isAzSshExtensionInstalled = () => {
  const { isInstalled } = AzInstall["az-ssh-extension"]!;
  if (!isInstalled) throw new Error("az-ssh-extension isInstalled is not set");
  return isInstalled();
};

beforeEach(() => {
  vi.clearAllMocks();
  // Miss the extension-directory fast path so tests exercise the az probe
  vi.stubEnv(
    "AZURE_EXTENSION_DIR",
    path.join(tmpdir(), "p0cli-test-no-such-dir")
  );
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("AzInstall['az-ssh-extension'].isInstalled", () => {
  it("skips the az probe entirely when the extension directory exists", async () => {
    // The az CLI costs ~1s of Python startup; the steady state must not pay it
    const extensionDir = mkdtempSync(path.join(tmpdir(), "p0cli-azext-"));
    try {
      mkdirSync(path.join(extensionDir, "ssh"));
      vi.stubEnv("AZURE_EXTENSION_DIR", extensionDir);

      await expect(isAzSshExtensionInstalled()).resolves.toBe(true);

      expect(mockExec).not.toHaveBeenCalled();
    } finally {
      rmSync(extensionDir, { recursive: true, force: true });
    }
  });

  it("finds the extension directory under AZURE_CONFIG_DIR", async () => {
    const configDir = mkdtempSync(path.join(tmpdir(), "p0cli-azcfg-"));
    try {
      mkdirSync(path.join(configDir, "cliextensions", "ssh"), {
        recursive: true,
      });
      vi.stubEnv("AZURE_EXTENSION_DIR", "");
      vi.stubEnv("AZURE_CONFIG_DIR", configDir);

      await expect(isAzSshExtensionInstalled()).resolves.toBe(true);

      expect(mockExec).not.toHaveBeenCalled();
    } finally {
      rmSync(configDir, { recursive: true, force: true });
    }
  });

  it("asks the Azure CLI when the extension directory is absent", async () => {
    mockExec.mockResolvedValueOnce({ code: 0, stdout: "", stderr: "" });

    await expect(isAzSshExtensionInstalled()).resolves.toBe(true);

    expect(mockExec).toHaveBeenCalledWith("az", [
      "extension",
      "show",
      "--name",
      "ssh",
    ]);
  });

  it("reports a missing extension when the az probe exits non-zero", async () => {
    mockExec.mockResolvedValueOnce({
      code: 1,
      stdout: "",
      stderr: "The extension ssh is not installed.",
    });

    await expect(isAzSshExtensionInstalled()).resolves.toBe(false);
  });

  it("reports a missing extension when the az binary cannot be spawned", async () => {
    mockExec.mockRejectedValueOnce(new Error("spawn az ENOENT"));

    await expect(isAzSshExtensionInstalled()).resolves.toBe(false);
  });
});

describe("AzInstall['az-ssh-extension']", () => {
  it("installs with the documented az extension command", () => {
    expect(AzInstall["az-ssh-extension"]!.commands.darwin).toEqual([
      "az extension add --name ssh",
    ]);
  });

  it("carries the pip failure hint for when the install command fails", () => {
    // The known failure mode of `az extension add`: the pip step dies.
    // cert-error.test.ts pins the per-platform content.
    expect(AzInstall["az-ssh-extension"]!.failureHint).toContain("az upgrade");
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
