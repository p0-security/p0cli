/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchIntegrationConfig } from "../../../drivers/api";
import { print2 } from "../../../drivers/stdio";
import { awsSshProvider } from "../../../plugins/aws/ssh";
import { azureBastionSshProvider } from "../../../plugins/azure/ssh-bastion";
import { TARGET_CONNECT_TIMEOUT_SECONDS } from "../../../plugins/azure/ssh-jump-host";
import { gcpSshProvider } from "../../../plugins/google/ssh";
import { selfHostedSshProvider } from "../../../plugins/self-hosted/ssh";
import { Authn } from "../../../types/identity";
import {
  getDefaultSudo,
  newSshProvider,
  newSshRequestErrorHandler,
  validateSshInstall,
} from "../ssh";
import { sys } from "typescript";
import { afterEach, beforeEach, describe, expect, it, Mock, vi } from "vitest";

vi.mock("../../../drivers/api");
vi.mock("../../../drivers/stdio", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../drivers/stdio")>()),
  print2: vi.fn(),
}));
vi.mock("typescript", async (importOriginal) => ({
  ...(await importOriginal<typeof import("typescript")>()),
  sys: { exit: vi.fn() },
}));

const mockFetchIntegrationConfig = fetchIntegrationConfig as Mock;
const mockPrint2 = print2 as Mock;
const mockExit = sys.exit as Mock;

const mockAuthn = {} as Authn;

const permissionShape = (permission: object) =>
  ({ permission }) as Parameters<typeof newSshProvider>[0];

const cliShape = (request: object) =>
  request as Parameters<typeof newSshProvider>[0];

const JUMP_HOST = { id: "jump-1", roleId: "jrole-1", publicIp: "4.154.21.27" };

beforeEach(() => {
  vi.clearAllMocks();
});

describe("newSshProvider", () => {
  describe("from the backend permission shape", () => {
    it.each([
      ["aws", awsSshProvider],
      ["gcloud", gcpSshProvider],
      ["self-hosted", selfHostedSshProvider],
    ] as const)("selects the %s provider", (provider, expected) => {
      expect(newSshProvider(permissionShape({ provider }))).toBe(expected);
    });

    it("selects the azure Bastion provider when the permission has no jump host", () => {
      expect(newSshProvider(permissionShape({ provider: "azure" }))).toBe(
        azureBastionSshProvider
      );
    });

    it("selects the azure jump-host provider when the permission has a jump host", () => {
      const provider = newSshProvider(
        permissionShape({ provider: "azure", jumpHost: JUMP_HOST })
      );

      expect(provider).not.toBe(azureBastionSshProvider);
      expect(provider.sshConnectTimeoutSeconds).toBe(
        TARGET_CONNECT_TIMEOUT_SECONDS
      );
    });
  });

  describe("from the CLI request shape", () => {
    it.each([
      ["aws", awsSshProvider],
      ["gcloud", gcpSshProvider],
      ["self-hosted", selfHostedSshProvider],
    ] as const)("selects the %s provider", (type, expected) => {
      expect(newSshProvider(cliShape({ type }))).toBe(expected);
    });

    it("selects the azure Bastion provider when the request has no jump host", () => {
      expect(
        newSshProvider(cliShape({ type: "azure", bastionId: "bastion-1" }))
      ).toBe(azureBastionSshProvider);
    });

    it("selects the azure jump-host provider when the request has a jump host", () => {
      const provider = newSshProvider(
        cliShape({ type: "azure", jumpHost: JUMP_HOST })
      );

      expect(provider).not.toBe(azureBastionSshProvider);
      expect(provider.sshConnectTimeoutSeconds).toBe(
        TARGET_CONNECT_TIMEOUT_SECONDS
      );
    });
  });

  it("returns the same jump-host provider singleton on every call, like every other provider", () => {
    const request = permissionShape({ provider: "azure", jumpHost: JUMP_HOST });

    expect(newSshProvider(request)).toBe(newSshProvider(request));
  });

  it("throws on an unknown provider", () => {
    expect(() => newSshProvider(cliShape({ type: "nonsense" }))).toThrow(
      /unexpected/i
    );
  });
});

describe("validateSshInstall", () => {
  const args = { debug: false } as Parameters<typeof validateSshInstall>[1];

  it("resolves when an installed item matches a supported provider", async () => {
    mockFetchIntegrationConfig.mockResolvedValue({
      config: { "iam-write": { "azure:sub-1": { state: "installed" } } },
    });

    await expect(validateSshInstall(mockAuthn, args)).resolves.toBeUndefined();
  });

  it("throws when no item is installed", async () => {
    mockFetchIntegrationConfig.mockResolvedValue({
      config: { "iam-write": { "aws:123": { state: "stale" } } },
    });

    await expect(validateSshInstall(mockAuthn, args)).rejects.toMatch(
      /not configured for SSH access/
    );
  });

  it("throws when the config document is missing entirely", async () => {
    mockFetchIntegrationConfig.mockResolvedValue(undefined);

    await expect(validateSshInstall(mockAuthn, args)).rejects.toMatch(
      /not configured for SSH access/
    );
  });

  it("only accepts items for the provider requested via --provider", async () => {
    mockFetchIntegrationConfig.mockResolvedValue({
      config: { "iam-write": { "aws:123": { state: "installed" } } },
    });

    await expect(
      validateSshInstall(mockAuthn, {
        ...args,
        provider: "azure",
      } as typeof args)
    ).rejects.toMatch(/not configured for SSH access/);
  });
});

describe("getDefaultSudo", () => {
  const original = process.env.P0_SSH_SUDO;

  afterEach(() => {
    if (original === undefined) delete process.env.P0_SSH_SUDO;
    else process.env.P0_SSH_SUDO = original;
  });

  it.each([
    [undefined, false],
    ["1", true],
    ["true", true],
    ["0", false],
    ["false", false],
    ["FALSE", false],
  ])("returns %s → %s", (value, expected) => {
    if (value === undefined) delete process.env.P0_SSH_SUDO;
    else process.env.P0_SSH_SUDO = value;

    expect(getDefaultSudo()).toBe(expected);
  });
});

describe("newSshRequestErrorHandler", () => {
  it("prints a username hint when no instance matches and the destination contains '@'", () => {
    newSshRequestErrorHandler("user@my-vm")(
      "Could not find any instances matching user@my-vm"
    );

    expect(mockPrint2).toHaveBeenCalledWith(
      "Could not find any instances matching user@my-vm"
    );
    expect(mockPrint2).toHaveBeenCalledWith(
      expect.stringMatching(/username should be omitted/i)
    );
    expect(mockExit).toHaveBeenCalledWith(1);
  });

  it("prints the error without a hint for other string errors", () => {
    newSshRequestErrorHandler("my-vm")("Some other failure");

    expect(mockPrint2).toHaveBeenCalledTimes(1);
    expect(mockPrint2).toHaveBeenCalledWith("Some other failure");
    expect(mockExit).toHaveBeenCalledWith(1);
  });

  it("exits without printing for non-string errors", () => {
    newSshRequestErrorHandler("my-vm")(new Error("boom"));

    expect(mockPrint2).not.toHaveBeenCalled();
    expect(mockExit).toHaveBeenCalledWith(1);
  });
});
