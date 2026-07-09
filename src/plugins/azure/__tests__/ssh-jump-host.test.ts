/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { CliPermissionSpec } from "../../../types/ssh";
import { exec } from "../../../util";
import { createTempDirectoryForKeys } from "../../ssh/shared";
import { azSetSubscription } from "../auth";
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
import path from "node:path";
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

vi.mock("../../../drivers/stdio", () => ({
  print2: vi.fn(),
}));

type AzureCliRequest = CliPermissionSpec<
  AzureSshPermissionSpec,
  AzureLocalData
>;

const LINUX_USER = "miguel.campos@permz.us";
const PRIVATE_IP = "10.1.0.4";
const JUMP_IP = "4.154.21.27";
const KEY_PATH = "/tmp";

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

const jumpHostPermission = (
  overrides: Partial<AzureSshPermission> = {}
): AzureSshPermission => ({
  ...PERMISSION_BASE,
  jumpHost: { id: "jump-1", roleId: "jrole-1", publicIp: JUMP_IP },
  ...overrides,
});

const jumpHostRequest = (overrides: Partial<AzureSshPermission> = {}) =>
  azureJumpHostSshProvider.requestToSsh(
    cliRequest(jumpHostPermission(overrides))
  );

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(exec).mockResolvedValue({ stdout: "", stderr: "" } as any);
  vi.mocked(azSetSubscription).mockResolvedValue(LINUX_USER);
  vi.mocked(createTempDirectoryForKeys).mockResolvedValue({
    path: KEY_PATH,
    cleanup: vi.fn().mockResolvedValue(undefined),
  });
});

describe("sshConnectTimeoutSeconds", () => {
  it("exceeds the inner jump-host hop's own ConnectTimeout, leaving it headroom for its own banner exchange", () => {
    expect(azureJumpHostSshProvider.sshConnectTimeoutSeconds).toBe(
      TARGET_CONNECT_TIMEOUT_SECONDS
    );
    expect(TARGET_CONNECT_TIMEOUT_SECONDS).toBeGreaterThan(
      JUMP_HOST_CONNECT_TIMEOUT_SECONDS
    );
  });
});

describe("requestToSsh", () => {
  it("maps a jump host request to the target's private IP", () => {
    const request = jumpHostRequest();

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

  it("throws when a jump host target has no private IP", () => {
    expect(() =>
      jumpHostRequest({
        resource: {
          ...PERMISSION_BASE.resource,
          networkInterface: {
            ...PERMISSION_BASE.resource.networkInterface,
            privateIp: undefined,
          },
        },
      })
    ).toThrow(/private IP/i);
  });

  it("throws when the jump host has no IP address", () => {
    expect(() =>
      jumpHostRequest({
        jumpHost: { id: "jump-1", roleId: "jrole-1", publicIp: "" },
      })
    ).toThrow(/jump host .* no IP/i);
  });
});

describe("setup", () => {
  const setupOptions = () => ({
    requestId: "request-1",
    abortController: new AbortController(),
    debug: false,
  });

  it("mints keys and bounds the outer hop's ConnectTimeout with headroom over the inner hop's", async () => {
    const result = await azureJumpHostSshProvider.setup!(
      {} as any,
      jumpHostRequest(),
      setupOptions()
    );

    expect(result.identityFile).toBe(path.join(KEY_PATH, AD_SSH_KEY_PRIVATE));
    expect(result.certificatePath).toBe(path.join(KEY_PATH, AD_CERT_FILENAME));
    expect(result.sshOptions).toEqual([
      `CertificateFile=${path.join(KEY_PATH, AD_CERT_FILENAME)}`,
      "StrictHostKeyChecking=no",
      "UserKnownHostsFile=/dev/null",
      `ConnectTimeout=${TARGET_CONNECT_TIMEOUT_SECONDS}`,
    ]);
  });

  it("tears down the temp key directory", async () => {
    const cleanup = vi.fn().mockResolvedValue(undefined);
    vi.mocked(createTempDirectoryForKeys).mockResolvedValue({
      path: KEY_PATH,
      cleanup,
    });

    const result = await azureJumpHostSshProvider.setup!(
      {} as any,
      jumpHostRequest(),
      setupOptions()
    );
    await result.teardown();

    expect(cleanup).toHaveBeenCalled();
  });

  it("throws when the Azure CLI login resolves to an unexpected linux user", async () => {
    vi.mocked(azSetSubscription).mockResolvedValue("someone-else@example.com");

    await expect(
      azureJumpHostSshProvider.setup!(
        {} as any,
        jumpHostRequest(),
        setupOptions()
      )
    ).rejects.toMatch(/different user name/i);
  });

  it("cleans up the temp key directory when cert generation fails", async () => {
    const cleanup = vi.fn().mockResolvedValue(undefined);
    vi.mocked(createTempDirectoryForKeys).mockResolvedValue({
      path: KEY_PATH,
      cleanup,
    });
    vi.mocked(exec).mockRejectedValue(
      Object.assign(new Error("boom"), { stdout: "", stderr: "" })
    );

    await expect(
      azureJumpHostSshProvider.setup!(
        {} as any,
        jumpHostRequest(),
        setupOptions()
      )
    ).rejects.toThrow();

    expect(cleanup).toHaveBeenCalled();
  });
});

describe("setupProxy", () => {
  it("mints a fresh cert for the jump-host hop and pins the port to 22", async () => {
    const result = await azureJumpHostSshProvider.setupProxy!(
      jumpHostRequest(),
      { debug: false, abortController: new AbortController() }
    );

    expect(result.port).toBe("22");
    expect(result.identityFile).toBe(path.join(KEY_PATH, AD_SSH_KEY_PRIVATE));
    expect(result.certificatePath).toBe(path.join(KEY_PATH, AD_CERT_FILENAME));
    await expect(result.teardown()).resolves.toBeUndefined();
  });

  it("mints keys independently from setup (ssh-proxy runs in a separate process)", async () => {
    await azureJumpHostSshProvider.setupProxy!(jumpHostRequest(), {
      debug: false,
      abortController: new AbortController(),
    });

    expect(azSetSubscription).toHaveBeenCalledTimes(1);
    expect(createTempDirectoryForKeys).toHaveBeenCalledTimes(1);
  });
});

describe("proxyCommand", () => {
  it("builds an SSH `-W` proxy through the jump host using the setup-minted credentials", () => {
    const request = jumpHostRequest();

    const command = azureJumpHostSshProvider.proxyCommand(request, undefined, {
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
    expect(() =>
      azureJumpHostSshProvider.proxyCommand(jumpHostRequest())
    ).toThrow(/keys were not generated/i);
  });
});

describe("connectionErrorMessage", () => {
  const request = jumpHostRequest();

  it("classifies a connect timeout to the jump host as the jump host being unreachable", () => {
    const message = azureJumpHostSshProvider.connectionErrorMessage!(
      `debug1: Connecting to ${JUMP_IP} [${JUMP_IP}] port 22.\n` +
        `ssh: connect to host ${JUMP_IP} port 22: Connection timed out`,
      request
    );

    expect(message).toMatch(/jump host/i);
    expect(message).toContain(JUMP_IP);
  });

  it("does not attribute a connect failure for some other host to the jump host", () => {
    const message = azureJumpHostSshProvider.connectionErrorMessage!(
      "ssh: connect to host 192.0.2.99 port 22: Connection refused",
      request
    );

    expect(message).toBeUndefined();
  });

  it("classifies a failed `-W` forward as the target VM being unreachable", () => {
    const message = azureJumpHostSshProvider.connectionErrorMessage!(
      "channel 0: open failed: connect failed: Connection timed out",
      request
    );

    expect(message).toMatch(/target VM/i);
    expect(message).toContain(PRIVATE_IP);
  });

  it("falls through to the raw error for unrelated stderr", () => {
    expect(
      azureJumpHostSshProvider.connectionErrorMessage!(
        "some unrelated ssh noise",
        request
      )
    ).toBeUndefined();
  });
});

describe("unprovisionedAccessPatterns", () => {
  const matches = (stderr: string) =>
    azureJumpHostSshProvider.unprovisionedAccessPatterns.some((p) =>
      p.pattern.test(stderr)
    );

  it("retries on a certificate rejection while the access role propagates", () => {
    expect(matches("Permission denied (publickey).")).toBe(true);
  });

  it("retries when the connection drops before the SSH banner (e.g. jump host unreachable)", () => {
    expect(
      matches("kex_exchange_identification: Connection closed by remote host")
    ).toBe(true);
    expect(matches("Connection closed by UNKNOWN port 65535")).toBe(true);
  });

  it("retries when the outer hop's ConnectTimeout expires during the target's banner exchange", () => {
    expect(
      matches(
        "ssh_exchange_identification: Connection timed out during banner exchange"
      )
    ).toBe(true);
    expect(matches("Connection to UNKNOWN port 65535 timed out")).toBe(true);
  });

  it("retries on the sudo propagation message", () => {
    expect(matches("Sorry, user miguel may not run sudo on my-vm.")).toBe(true);
  });
});
