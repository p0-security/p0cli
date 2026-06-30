/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { newSshProvider } from "../../../commands/shared/ssh";
import { Authn } from "../../../types/identity";
import { PermissionRequest } from "../../../types/request";
import { CliPermissionSpec } from "../../../types/ssh";
import { generateAzureSshKeys } from "../keygen";
import { azureBastionSshProvider } from "../ssh-bastion";
import {
  JUMP_HOST_CONNECT_TIMEOUT_SECONDS,
  newAzureJumpHostSshProvider,
} from "../ssh-jump-host";
import {
  AzureLocalData,
  AzureSshPermission,
  AzureSshPermissionSpec,
} from "../types";
import { beforeEach, describe, expect, it, Mock, vi } from "vitest";

vi.mock("../keygen", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../keygen")>()),
  generateAzureSshKeys: vi.fn(),
}));

const mockGenerateAzureSshKeys = generateAzureSshKeys as Mock;

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
  alias: undefined,
  group: undefined,
  sudo: undefined,
  region: "eastus",
  zone: undefined,
  bastionHost: undefined,
  jumpHost: undefined,
  accessRoleId: "role-abc",
  resource: {
    instanceName: "my-vm",
    instanceId: "/subscriptions/sub-1/.../my-vm",
    subscriptionId: "sub-1",
    subscriptionName: "sub-name",
    resourceGroupId: "rg-1",
    groupTag: undefined,
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
  jumpHost: { id: "jump-1", roleId: "jrole-1", ip: JUMP_IP },
  ...overrides,
});

const bastionPermission = (): AzureSshPermission => ({
  ...PERMISSION_BASE,
  bastionHost: { id: "bastion-1" },
});

beforeEach(() => {
  vi.clearAllMocks();
  mockGenerateAzureSshKeys.mockResolvedValue({
    privateKeyPath: "/tmp/id_rsa",
    certificatePath: "/tmp/cert.pub",
    cleanup: vi.fn(async () => {}),
  });
});

describe("newSshProvider", () => {
  it("selects the jump-host provider when the permission has a jump host", () => {
    const provider = newSshProvider(permissionRequest(jumpHostPermission()));

    expect(provider).not.toBe(azureBastionSshProvider);
    expect(provider.sshConnectTimeoutSeconds).toBe(
      JUMP_HOST_CONNECT_TIMEOUT_SECONDS
    );
  });

  it("selects the Bastion provider when the permission has no jump host", () => {
    const provider = newSshProvider(permissionRequest(bastionPermission()));

    expect(provider).toBe(azureBastionSshProvider);
  });

  it("selects by the CLI request shape as well (used by ssh-proxy and spawned sessions)", () => {
    const jumpProvider = newSshProvider({
      type: "azure",
      jumpHost: { id: "jump-1", roleId: "jrole-1", ip: JUMP_IP },
    } as any);
    const bastionProvider = newSshProvider({
      type: "azure",
      bastionId: "bastion-1",
    } as any);

    expect(jumpProvider.sshConnectTimeoutSeconds).toBe(
      JUMP_HOST_CONNECT_TIMEOUT_SECONDS
    );
    expect(bastionProvider).toBe(azureBastionSshProvider);
  });
});

describe("requestToSsh", () => {
  it("maps a jump host request to the target's private IP", () => {
    const request = newAzureJumpHostSshProvider().requestToSsh(
      cliRequest(jumpHostPermission())
    );

    expect(request.id).toBe(PRIVATE_IP);
    expect(request.jumpHost).toEqual({
      id: "jump-1",
      roleId: "jrole-1",
      ip: JUMP_IP,
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
      newAzureJumpHostSshProvider().requestToSsh(cliRequest(permission))
    ).toThrow(/private IP/i);
  });

  it("throws when the jump host has no IP address", () => {
    const permission = jumpHostPermission({
      jumpHost: { id: "jump-1", roleId: "jrole-1", ip: undefined },
    });

    expect(() =>
      newAzureJumpHostSshProvider().requestToSsh(cliRequest(permission))
    ).toThrow(/jump host .* no IP/i);
  });
});

describe("proxyCommand", () => {
  it("builds an SSH `-W` proxy through the jump host with the keys minted by generateKeys", async () => {
    const provider = newAzureJumpHostSshProvider();
    const request = provider.requestToSsh(cliRequest(jumpHostPermission()));

    await provider.generateKeys!({} as Authn, request, { requestId: "req-1" });
    const command = provider.proxyCommand(request);

    expect(command).toEqual([
      "ssh",
      "-i",
      "/tmp/id_rsa",
      "-o",
      "CertificateFile=/tmp/cert.pub",
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

  it("throws if keys were not generated for this provider instance", () => {
    const provider = newAzureJumpHostSshProvider();
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

describe("unprovisionedAccessPatterns", () => {
  const matches = (
    provider: { unprovisionedAccessPatterns: readonly { pattern: RegExp }[] },
    stderr: string
  ) => provider.unprovisionedAccessPatterns.some((p) => p.pattern.test(stderr));

  describe("jump host", () => {
    const provider = newAzureJumpHostSshProvider();

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
