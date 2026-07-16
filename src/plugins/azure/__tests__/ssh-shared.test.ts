/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../../drivers/stdio";
import { exec } from "../../../util";
import { createTempDirectoryForKeys } from "../../ssh/shared";
import { azSetSubscription } from "../auth";
import { ensureAzInstall } from "../install";
import {
  AD_CERT_FILENAME,
  AD_SSH_KEY_PRIVATE,
  azSshCertCommand,
  azureSshLoginReproCommands,
  azureSshProviderBase,
  generateSshKeyAndAzureAdCert,
} from "../ssh-shared";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../drivers/stdio", () => ({
  print2: vi.fn(),
}));

// Spread the original so the real osSafeCommand (used by azSshCertCommand)
// keeps working; only stub the subprocess execution.
vi.mock("../../../util", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../util")>()),
  exec: vi.fn(),
}));

// Spread the original so the real az command builders (used by
// azureSshLoginReproCommands) keep working; only stub the login flow.
vi.mock("../auth", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../auth")>()),
  azSetSubscription: vi.fn(),
}));

vi.mock("../install", () => ({
  ensureAzInstall: vi.fn(),
}));

vi.mock("../../ssh/shared", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../ssh/shared")>()),
  createTempDirectoryForKeys: vi.fn(),
}));

const mockExec = vi.mocked(exec);
const mockPrint2 = vi.mocked(print2);
const mockAzSetSubscription = vi.mocked(azSetSubscription);
const mockEnsureAzInstall = vi.mocked(ensureAzInstall);
const mockCreateTempDirectoryForKeys = vi.mocked(createTempDirectoryForKeys);

const KEY_PATH = path.join("tmp", "p0cli-keys");

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("azSshCertCommand", () => {
  it("builds an `az ssh cert` command targeting the cert file in the key path", () => {
    expect(azSshCertCommand(KEY_PATH)).toEqual({
      command: "az",
      args: ["ssh", "cert", "--file", path.join(KEY_PATH, AD_CERT_FILENAME)],
    });
  });
});

describe("generateSshKeyAndAzureAdCert", () => {
  it("executes the cert command with check enabled and prints nothing without debug", async () => {
    mockExec.mockResolvedValue({ stdout: "ok", stderr: "" } as any);

    await generateSshKeyAndAzureAdCert(KEY_PATH);

    expect(mockExec).toHaveBeenCalledWith(
      "az",
      ["ssh", "cert", "--file", path.join(KEY_PATH, AD_CERT_FILENAME)],
      { check: true }
    );
    expect(mockPrint2).not.toHaveBeenCalled();
  });

  it("prints progress and the command output when debug is enabled", async () => {
    mockExec.mockResolvedValue({
      stdout: "generated cert",
      stderr: "some warning",
    } as any);

    await generateSshKeyAndAzureAdCert(KEY_PATH, { debug: true });

    expect(mockPrint2).toHaveBeenCalledWith(
      "Generating Azure AD SSH certificate..."
    );
    expect(mockPrint2).toHaveBeenCalledWith("generated cert");
    expect(mockPrint2).toHaveBeenCalledWith("some warning");
  });

  it("prints the failed command's output and rejects with a descriptive error", async () => {
    mockExec.mockRejectedValue(
      Object.assign(new Error("exited with code 1"), {
        stdout: "az stdout",
        stderr: "az stderr",
      })
    );

    await expect(generateSshKeyAndAzureAdCert(KEY_PATH)).rejects.toMatch(
      /Failed to generate Azure AD SSH certificate: Error: exited with code 1/
    );

    expect(mockPrint2).toHaveBeenCalledWith("az stdout");
    expect(mockPrint2).toHaveBeenCalledWith("az stderr");
  });

  it("rejects with an actionable hint when the `ssh` extension is missing and its install fails", async () => {
    mockExec.mockRejectedValue(
      Object.assign(new Error("exited with code 1"), {
        stdout: "",
        stderr:
          "WARNING: The command requires the extension ssh. It will be installed first.\n" +
          "ERROR: An error occurred. Pip failed with status code 1. Use --debug for more information.\n",
      })
    );

    await expect(generateSshKeyAndAzureAdCert(KEY_PATH)).rejects.toMatch(
      /az extension add --name ssh/
    );
  });
});

describe("azureSshLoginReproCommands", () => {
  const request = {
    directoryId: "my-tenant-id",
    subscriptionId: "my-subscription-id",
  };

  it("returns the login and cert-generation commands using the identity file's directory", () => {
    const commands = azureSshLoginReproCommands(request, {
      sshOptions: [],
      identityFile: path.join(KEY_PATH, AD_SSH_KEY_PRIVATE),
      port: "50022",
      teardown: async () => {},
    });

    expect(commands).toEqual([
      "az account clear",
      "az login --scope https://management.core.windows.net//.default --tenant my-tenant-id",
      "az account set --subscription my-subscription-id",
      `mkdir ${KEY_PATH}`,
      `az ssh cert --file ${path.join(KEY_PATH, AD_CERT_FILENAME)}`,
    ]);
  });

  it("falls back to a key path in the home directory without additional data", () => {
    vi.stubEnv("HOME", path.join("home", "p0user"));

    const commands = azureSshLoginReproCommands(request);

    const keyPath = path.join("home", "p0user", "p0cli-azure-ssh-keys");
    expect(commands).toContain(`mkdir ${keyPath}`);
    expect(commands).toContain(
      `az ssh cert --file ${path.join(keyPath, AD_CERT_FILENAME)}`
    );
  });

  it("uses USERPROFILE for the key path when HOME is not set", () => {
    vi.stubEnv("HOME", undefined);
    vi.stubEnv("USERPROFILE", path.join("Users", "p0user"));

    const commands = azureSshLoginReproCommands(request);

    expect(commands).toContain(
      `mkdir ${path.join("Users", "p0user", "p0cli-azure-ssh-keys")}`
    );
  });
});

describe("azureSshProviderBase", () => {
  describe("cloudProviderLogin", () => {
    it("is a no-op since login happens during provider setup", async () => {
      await expect(
        azureSshProviderBase.cloudProviderLogin()
      ).resolves.toBeUndefined();
    });
  });

  describe("ensureInstall", () => {
    it("resolves when the Azure CLI is installed", async () => {
      mockEnsureAzInstall.mockResolvedValue(true);

      await expect(
        azureSshProviderBase.ensureInstall()
      ).resolves.toBeUndefined();
    });

    it("rejects with an install prompt when the Azure CLI is missing", async () => {
      mockEnsureAzInstall.mockResolvedValue(false);

      await expect(azureSshProviderBase.ensureInstall()).rejects.toMatch(
        /installing the Azure CLI/
      );
    });
  });

  describe("preTestAccessPropagationArgs", () => {
    it("returns a non-interactive `sudo -nv` pre-test for sudo commands", () => {
      expect(
        azureSshProviderBase.preTestAccessPropagationArgs({
          sudo: true,
          destination: "my-vm",
          arguments: ["whoami"],
        })
      ).toEqual({
        sudo: true,
        destination: "my-vm",
        command: "sudo",
        arguments: ["-nv"],
      });
    });

    it("skips pre-testing for non-sudo commands", () => {
      expect(
        azureSshProviderBase.preTestAccessPropagationArgs({
          destination: "my-vm",
          arguments: [],
        })
      ).toBeUndefined();
    });
  });

  describe("generateKeys", () => {
    it("sets the subscription and generates keys in a temporary directory", async () => {
      mockCreateTempDirectoryForKeys.mockResolvedValue({
        path: KEY_PATH,
        cleanup: vi.fn(),
      });
      mockExec.mockResolvedValue({ stdout: "", stderr: "" } as any);

      const request = {
        subscriptionId: "my-subscription-id",
        directoryId: "my-tenant-id",
      } as any;
      const options = { requestId: "request-1", debug: false };

      await expect(
        azureSshProviderBase.generateKeys({} as any, request, options)
      ).resolves.toEqual({
        privateKeyPath: path.join(KEY_PATH, AD_SSH_KEY_PRIVATE),
        certificatePath: path.join(KEY_PATH, AD_CERT_FILENAME),
      });

      expect(mockAzSetSubscription).toHaveBeenCalledWith(request, options);
    });
  });

  describe("toCliRequest", () => {
    const request = {
      principal: "user@example.com",
      generated: { linuxUserName: "generated-user" },
    } as any;

    it("copies the generated linux user name into cliLocalData", async () => {
      await expect(
        azureSshProviderBase.toCliRequest(request)
      ).resolves.toMatchObject({
        cliLocalData: { linuxUserName: "generated-user" },
      });
    });

    it("falls back to the principal when no linux user name was generated", async () => {
      await expect(
        azureSshProviderBase.toCliRequest({
          ...request,
          generated: {},
        })
      ).resolves.toMatchObject({
        cliLocalData: { linuxUserName: "user@example.com" },
      });
    });
  });
});
