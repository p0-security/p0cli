/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { newSshProvider } from "../../../commands/shared/ssh";
import { PermissionRequest } from "../../../types/request";
import { CliPermissionSpec } from "../../../types/ssh";
import { exec } from "../../../util";
import { createTempDirectoryForKeys } from "../../ssh/shared";
import { azSetSubscription } from "../auth";
import { azureBastionSshProvider } from "../ssh-bastion";
import {
  JUMP_HOST_CONNECT_TIMEOUT_SECONDS,
  TARGET_CONNECT_TIMEOUT_SECONDS,
  azureJumpHostSshProvider,
} from "../ssh-jump-host";
import { AD_CERT_FILENAME, AD_SSH_KEY_PRIVATE } from "../ssh-shared";
import {
  AzureLocalData,
  AzureSshPermission,
  AzureSshPermissionSpec,
} from "../types";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Key minting shells out to the Azure CLI; stub the subprocess and login
// boundaries (same style as ssh-shared.test.ts) and pin the temp key directory.
vi.mock("../../../util", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../util")>()),
  exec: vi.fn(),
}));

vi.mock("../auth", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../auth")>()),
  azSetSubscription: vi.fn(),
}));

vi.mock("../../ssh/shared", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../ssh/shared")>()),
  createTempDirectoryForKeys: vi.fn(),
}));

type AzureCliRequest = CliPermissionSpec<
  AzureSshPermissionSpec,
  AzureLocalData
>;

const LINUX_USER = "miguel.campos@permz.us";
const PRIVATE_IP = "10.1.0.4";
const JUMP_IP = "4.154.21.27";

const PERMISSION_BASE: AzureSshPermission = {
  provider: "azure",
  publicKey: "pub-key",
  destination: "my-vm",
  parent: undefined,
  group: undefined,
  principal: LINUX_USER,
  resource: {
    instanceName: "my-vm",
    instanceId: "/subscriptions/sub-1/.../my-vm",
    subscriptionId: "sub-1",
    subscriptionName: "sub-name",
    resourceGroupId: "rg-1",
    region: "eastus",
    networkInterface: {
      id: "nic-1",
      subnetId: "subnet-1",
      privateIp: PRIVATE_IP,
    },
  },
};

const cliRequest = (permission: AzureSshPermission): AzureCliRequest => ({
  type: "ssh",
  permission,
  generated: { linuxUserName: LINUX_USER, directoryId: "dir-1" },
  cliLocalData: { linuxUserName: LINUX_USER },
});

const permissionRequest = (
  permission: AzureSshPermission
): PermissionRequest<AzureSshPermissionSpec> => ({
  type: "ssh",
  permission,
  generated: { linuxUserName: LINUX_USER, directoryId: "dir-1" },
  status: "DONE",
  principal: LINUX_USER,
});

const jumpHostPermission = (
  overrides: Partial<AzureSshPermission> = {}
): AzureSshPermission => ({
  ...PERMISSION_BASE,
  jumpHost: { id: "jump-1", roleId: "jrole-1", publicIp: JUMP_IP },
  ...overrides,
});

const bastionPermission = (): AzureSshPermission => ({
  ...PERMISSION_BASE,
  bastionHost: { id: "bastion-1" },
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(exec).mockResolvedValue({ stdout: "", stderr: "" } as any);
  vi.mocked(azSetSubscription).mockResolvedValue(LINUX_USER);
  vi.mocked(createTempDirectoryForKeys).mockResolvedValue({
    path: "/tmp",
    cleanup: async () => {},
  });
});

describe("newSshProvider", () => {
  it("selects the jump-host provider when the permission has a jump host", () => {
    const provider = newSshProvider(permissionRequest(jumpHostPermission()));

    expect(provider).not.toBe(azureBastionSshProvider);
    expect(provider.sshConnectTimeoutSeconds).toBe(
      TARGET_CONNECT_TIMEOUT_SECONDS
    );
  });

  it("selects the Bastion provider when the permission has no jump host", () => {
    const provider = newSshProvider(permissionRequest(bastionPermission()));

    expect(provider).toBe(azureBastionSshProvider);
  });

  it("selects by the CLI request shape as well (used by ssh-proxy and spawned sessions)", () => {
    const jumpProvider = newSshProvider({
      type: "azure",
      jumpHost: { id: "jump-1", roleId: "jrole-1", publicIp: JUMP_IP },
    } as any);
    const bastionProvider = newSshProvider({
      type: "azure",
      bastionId: "bastion-1",
    } as any);

    expect(jumpProvider.sshConnectTimeoutSeconds).toBe(
      TARGET_CONNECT_TIMEOUT_SECONDS
    );
    expect(bastionProvider).toBe(azureBastionSshProvider);
  });
});

describe("requestToSsh", () => {
  it("maps a jump host request to the target's private IP", () => {
    const request = azureJumpHostSshProvider.requestToSsh(
      cliRequest(jumpHostPermission())
    );

    expect(request.id).toBe(PRIVATE_IP);
    expect(request.jumpHost).toEqual({
      id: "jump-1",
      roleId: "jrole-1",
      publicIp: JUMP_IP,
    });
    expect(request.bastionId).toBeUndefined();
    expect(request.privateIp).toBe(PRIVATE_IP);
    expect(request.linuxUserName).toBe(LINUX_USER);
  });

  it("maps a bastion host request to localhost", () => {
    const request = azureBastionSshProvider.requestToSsh(
      cliRequest(bastionPermission())
    );

    expect(request.id).toBe("localhost");
    expect(request.bastionId).toBe("bastion-1");
    expect(request.jumpHost).toBeUndefined();
  });

  it("throws when neither a jump host nor a bastion host is present", () => {
    expect(() =>
      azureBastionSshProvider.requestToSsh(cliRequest(PERMISSION_BASE))
    ).toThrow(/not reachable/i);
  });

  it("throws when a jump host target has no private IP", () => {
    const permission = jumpHostPermission({
      resource: {
        ...PERMISSION_BASE.resource,
        networkInterface: {
          ...PERMISSION_BASE.resource.networkInterface,
          privateIp: undefined,
        },
      },
    });

    expect(() =>
      azureJumpHostSshProvider.requestToSsh(cliRequest(permission))
    ).toThrow(/private IP/i);
  });

  it("throws when the jump host has no IP address", () => {
    const permission = jumpHostPermission({
      jumpHost: { id: "jump-1", roleId: "jrole-1", publicIp: "" },
    });

    expect(() =>
      azureJumpHostSshProvider.requestToSsh(cliRequest(permission))
    ).toThrow(/jump host .* no IP/i);
  });
});

describe("proxyCommand", () => {
  it("builds an SSH `-W` proxy through the jump host using the setup-minted credentials", () => {
    const provider = azureJumpHostSshProvider;
    const request = provider.requestToSsh(cliRequest(jumpHostPermission()));

    const command = provider.proxyCommand(request, undefined, {
      identityFile: `/tmp/${AD_SSH_KEY_PRIVATE}`,
      certificatePath: `/tmp/${AD_CERT_FILENAME}`,
    });

    expect(command).toEqual([
      "ssh",
      "-F",
      "/dev/null",
      "-i",
      `/tmp/${AD_SSH_KEY_PRIVATE}`,
      "-o",
      `CertificateFile=/tmp/${AD_CERT_FILENAME}`,
      "-o",
      "StrictHostKeyChecking=no",
      "-o",
      "UserKnownHostsFile=/dev/null",
      "-o",
      `ConnectTimeout=${JUMP_HOST_CONNECT_TIMEOUT_SECONDS}`,
      "-o",
      "BatchMode=yes",
      "-W",
      `${PRIVATE_IP}:22`,
      `${LINUX_USER}@${JUMP_IP}`,
    ]);
  });

  it("throws if no credentials were minted for this jump-host connection", () => {
    const provider = azureJumpHostSshProvider;
    const request = provider.requestToSsh(cliRequest(jumpHostPermission()));

    expect(() => provider.proxyCommand(request)).toThrow(
      /keys were not generated/i
    );
  });

  it("connects to the local Bastion tunnel for a bastion request", () => {
    const request = azureBastionSshProvider.requestToSsh(
      cliRequest(bastionPermission())
    );

    const command = azureBastionSshProvider.proxyCommand(request, "50022");

    // nc on Unix/Mac, ncat on Windows; either way connects to the local tunnel port.
    expect(command[0]).toMatch(/^nc(at)?$/);
    expect(command.slice(1)).toEqual(["localhost", "50022"]);
  });
});

describe("connectionErrorMessage", () => {
  const provider = azureJumpHostSshProvider;
  const request = provider.requestToSsh(cliRequest(jumpHostPermission()));

  it("classifies a connect timeout to the jump host as the jump host being unreachable", () => {
    const message = provider.connectionErrorMessage!(
      `debug1: Connecting to ${JUMP_IP} [${JUMP_IP}] port 22.\n` +
        `ssh: connect to host ${JUMP_IP} port 22: Connection timed out`,
      request
    );

    expect(message).toMatch(/jump host/i);
    expect(message).toContain(JUMP_IP);
  });

  it("does not attribute a connect failure for some other host to the jump host", () => {
    const message = provider.connectionErrorMessage!(
      "ssh: connect to host 192.0.2.99 port 22: Connection refused",
      request
    );

    expect(message).toBeUndefined();
  });

  it("classifies a failed `-W` forward as the target VM being unreachable", () => {
    const message = provider.connectionErrorMessage!(
      "channel 0: open failed: connect failed: Connection timed out",
      request
    );

    expect(message).toMatch(/target VM/i);
    expect(message).toContain(PRIVATE_IP);
  });

  it("falls through to the raw error for unrelated stderr", () => {
    expect(
      provider.connectionErrorMessage!("some unrelated ssh noise", request)
    ).toBeUndefined();
  });
});

describe("unprovisionedAccessPatterns", () => {
  const matches = (
    provider: { unprovisionedAccessPatterns: readonly { pattern: RegExp }[] },
    stderr: string
  ) => provider.unprovisionedAccessPatterns.some((p) => p.pattern.test(stderr));

  describe("jump host", () => {
    const provider = azureJumpHostSshProvider;

    it("retries on a certificate rejection while the access role propagates", () => {
      expect(matches(provider, "Permission denied (publickey).")).toBe(true);
    });

    it("retries when the connection drops before the SSH banner (e.g. jump host unreachable)", () => {
      expect(
        matches(
          provider,
          "kex_exchange_identification: Connection closed by remote host"
        )
      ).toBe(true);
      expect(matches(provider, "Connection closed by UNKNOWN port 65535")).toBe(
        true
      );
    });

    it("retries when the outer hop's ConnectTimeout expires during the target's banner exchange", () => {
      expect(
        matches(
          provider,
          "ssh_exchange_identification: Connection timed out during banner exchange"
        )
      ).toBe(true);
      expect(
        matches(provider, "Connection to UNKNOWN port 65535 timed out")
      ).toBe(true);
    });

    it("retries on the sudo propagation message", () => {
      expect(
        matches(provider, "Sorry, user miguel may not run sudo on my-vm.")
      ).toBe(true);
    });
  });

  describe("bastion", () => {
    it("retries on the sudo propagation message only", () => {
      expect(
        matches(
          azureBastionSshProvider,
          "Sorry, user miguel may not run sudo on my-vm."
        )
      ).toBe(true);
      expect(
        matches(azureBastionSshProvider, "Permission denied (publickey).")
      ).toBe(false);
    });
  });
});
