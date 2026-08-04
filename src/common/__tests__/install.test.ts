/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print1, print2 } from "../../drivers/stdio";
import { spawnWithCleanEnv } from "../../util";
import { ensureInstall, InstallMetadata } from "../install";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import which from "which";

const { mockIsTTY, mockPrompt } = vi.hoisted(() => ({
  mockIsTTY: vi.fn(),
  mockPrompt: vi.fn(),
}));

vi.mock("typescript", async (importOriginal) => ({
  ...(await importOriginal<typeof import("typescript")>()),
  sys: { writeOutputIsTTY: mockIsTTY },
}));

vi.mock("inquirer", () => ({
  default: { prompt: mockPrompt },
}));

vi.mock("which", () => ({ default: vi.fn() }));

vi.mock("../../drivers/stdio", () => ({
  print1: vi.fn(),
  print2: vi.fn(),
}));

vi.mock("../../util", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../util")>()),
  spawnWithCleanEnv: vi.fn(),
}));

// The guided-install paths are darwin-only; pin the platform so the tests
// behave identically on any CI runner.
vi.mock("node:os", async (importOriginal) => {
  const original = await importOriginal<typeof import("node:os")>();
  const platform = () => "darwin" as const;
  return { ...original, platform, default: { ...original, platform } };
});

const mockWhich = vi.mocked(which as unknown as (...args: any[]) => any);
const mockSpawn = vi.mocked(spawnWithCleanEnv);
const mockPrint1 = vi.mocked(print1);
const mockPrint2 = vi.mocked(print2);

/** A child process stub that reports the given exit code */
const fakeChild = (code: number) =>
  ({
    on: (event: string, callback: (arg: number) => void) => {
      if (event === "exit") setImmediate(() => callback(code));
    },
  }) as any;

const INSTALL_COMMAND = "fake-tool install --now";

const newInstallData = (
  isInstalled?: () => Promise<boolean>,
  failureHint?: string
): Readonly<Record<"fake-tool", InstallMetadata>> => ({
  "fake-tool": {
    label: "the Fake Tool",
    commands: { darwin: [INSTALL_COMMAND] },
    ...(isInstalled ? { isInstalled } : {}),
    ...(failureHint ? { failureHint } : {}),
  },
});

const printed = (mock: typeof mockPrint2) =>
  mock.mock.calls.map((call) => call[0]).join("\n");

const originalStdinIsTTY = process.stdin.isTTY;
const setStdinTTY = (value: boolean | undefined) =>
  Object.defineProperty(process.stdin, "isTTY", { value, configurable: true });

beforeEach(() => {
  vi.clearAllMocks();
  mockIsTTY.mockReturnValue(true);
  setStdinTTY(true);
});

afterEach(() => {
  setStdinTTY(originalStdinIsTTY);
});

describe("ensureInstall", () => {
  describe("isInstalled overrides", () => {
    it("trusts a custom isInstalled check instead of the PATH lookup", async () => {
      const isInstalled = vi.fn().mockResolvedValue(true);

      await expect(
        ensureInstall(["fake-tool"], newInstallData(isInstalled))
      ).resolves.toBe(true);

      expect(isInstalled).toHaveBeenCalled();
      expect(mockWhich).not.toHaveBeenCalled();
      expect(mockPrompt).not.toHaveBeenCalled();
    });

    it("falls back to the PATH lookup without a custom check", async () => {
      mockWhich.mockResolvedValue("/usr/local/bin/fake-tool");

      await expect(
        ensureInstall(["fake-tool"], newInstallData())
      ).resolves.toBe(true);

      expect(mockWhich).toHaveBeenCalledWith("fake-tool", { nothrow: true });
    });
  });

  describe("interactivity gate", () => {
    it("prints the install commands without prompting when stdout is not a TTY", async () => {
      mockIsTTY.mockReturnValue(false);

      await expect(
        ensureInstall(
          ["fake-tool"],
          newInstallData(vi.fn().mockResolvedValue(false))
        )
      ).resolves.toBe(false);

      expect(mockPrompt).not.toHaveBeenCalled();
      expect(mockPrint1).toHaveBeenCalledWith(`  ${INSTALL_COMMAND}`);
    });

    it("prints the install commands without prompting when stdin is not a TTY", async () => {
      // e.g. `p0 ssh host cmd < data.txt`: a prompt would consume the user's
      // redirected data as its answer
      setStdinTTY(undefined);

      await expect(
        ensureInstall(
          ["fake-tool"],
          newInstallData(vi.fn().mockResolvedValue(false))
        )
      ).resolves.toBe(false);

      expect(mockPrompt).not.toHaveBeenCalled();
      expect(mockPrint1).toHaveBeenCalledWith(`  ${INSTALL_COMMAND}`);
    });
  });

  describe("guided installation", () => {
    it("returns true when the accepted install succeeds", async () => {
      const isInstalled = vi
        .fn()
        .mockResolvedValueOnce(false) // pre-install check
        .mockResolvedValue(true); // post-install recheck
      mockPrompt.mockResolvedValueOnce({ isGuided: true });
      mockSpawn.mockReturnValueOnce(fakeChild(0));

      await expect(
        ensureInstall(["fake-tool"], newInstallData(isInstalled))
      ).resolves.toBe(true);

      expect(mockSpawn).toHaveBeenCalledWith(
        "bash",
        ["-c", INSTALL_COMMAND],
        expect.objectContaining({ stdio: "inherit" })
      );
    });

    it("falls back to the manual commands when the accepted install fails", async () => {
      mockPrompt.mockResolvedValueOnce({ isGuided: true });
      mockSpawn.mockReturnValueOnce(fakeChild(1));

      await expect(
        ensureInstall(
          ["fake-tool"],
          newInstallData(vi.fn().mockResolvedValue(false))
        )
      ).resolves.toBe(false);

      expect(printed(mockPrint2)).toContain("Automatic installation failed");
      expect(mockPrint1).toHaveBeenCalledWith(`  ${INSTALL_COMMAND}`);
    });

    it("prints the manual commands when the user declines", async () => {
      mockPrompt.mockResolvedValueOnce({ isGuided: false });

      await expect(
        ensureInstall(
          ["fake-tool"],
          newInstallData(vi.fn().mockResolvedValue(false))
        )
      ).resolves.toBe(false);

      expect(mockSpawn).not.toHaveBeenCalled();
      expect(mockPrint1).toHaveBeenCalledWith(`  ${INSTALL_COMMAND}`);
    });
  });

  describe("failure hints", () => {
    it("prints an item's failureHint after its manual commands", async () => {
      mockIsTTY.mockReturnValue(false);
      const hint = "If that command fails, try turning it off and on again.";

      await expect(
        ensureInstall(
          ["fake-tool"],
          newInstallData(vi.fn().mockResolvedValue(false), hint)
        )
      ).resolves.toBe(false);

      expect(printed(mockPrint2)).toContain(hint);
    });

    it("prints the failureHint when a guided install fails", async () => {
      mockPrompt.mockResolvedValueOnce({ isGuided: true });
      mockSpawn.mockReturnValueOnce(fakeChild(1));
      const hint = "If that command fails, try turning it off and on again.";

      await expect(
        ensureInstall(
          ["fake-tool"],
          newInstallData(vi.fn().mockResolvedValue(false), hint)
        )
      ).resolves.toBe(false);

      expect(printed(mockPrint2)).toContain(hint);
    });
  });
});
