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
import { azureBastionSshProvider } from "../ssh-bastion";
import { AD_CERT_FILENAME, AD_SSH_KEY_PRIVATE } from "../ssh-shared";
import { trySpawnBastionTunnel } from "../tunnel";
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

vi.mock("../tunnel", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../tunnel")>()),
  trySpawnBastionTunnel: vi.fn(),
}));

vi.mock("../../../drivers/stdio", () => ({
  print2: vi.fn(),
}));

type AzureCliRequest = CliPermissionSpec<
  AzureSshPermissionSpec,
  AzureLocalData
>;

const LINUX_USER = "miguel.campos@permz.us";
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
      privateIp: "10.1.0.4",
    },
  },
};

const bastionPermission = (): AzureSshPermission => ({
  ...PERMISSION_BASE,
  bastionHost: { id: "bastion-1" },
});

const cliRequest = (permission: AzureSshPermission): AzureCliRequest => ({
  type: "ssh",
  permission,
  generated: { linuxUserName: LINUX_USER, directoryId: "dir-1" },
  cliLocalData: { linuxUserName: LINUX_USER },
});

const bastionRequest = () =>
  azureBastionSshProvider.requestToSsh(cliRequest(bastionPermission()));

const tunnelMeta = (killTunnel: () => Promise<void> = vi.fn()) => ({
  killTunnel,
  tunnelLocalPort: "50123",
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(exec).mockResolvedValue({ stdout: "", stderr: "" } as any);
  vi.mocked(azSetSubscription).mockResolvedValue(LINUX_USER);
  vi.mocked(createTempDirectoryForKeys).mockResolvedValue({
    path: KEY_PATH,
    cleanup: vi.fn().mockResolvedValue(undefined),
  });
  vi.mocked(trySpawnBastionTunnel).mockResolvedValue(tunnelMeta());
});

describe("requestToSsh", () => {
  it("maps a bastion host request to localhost", () => {
    const request = bastionRequest();

    expect(request.id).toBe("localhost");
    expect(request.bastionId).toBe("bastion-1");
    expect(request.linuxUserName).toBe(LINUX_USER);
  });

  it("throws when no bastion host is present", () => {
    expect(() =>
      azureBastionSshProvider.requestToSsh(cliRequest(PERMISSION_BASE))
    ).toThrow(/not reachable/i);
  });
});

describe("proxyCommand", () => {
  it("connects to the local Bastion tunnel on the given port", () => {
    const command = azureBastionSshProvider.proxyCommand(
      bastionRequest(),
      "50022"
    );

    // nc on Unix/Mac, ncat on Windows; either way connects to the local tunnel port.
    expect(command[0]).toMatch(/^nc(at)?$/);
    expect(command.slice(1)).toEqual(["localhost", "50022"]);
  });

  it("falls back to port 22 when no port is given", () => {
    const command = azureBastionSshProvider.proxyCommand(bastionRequest());

    expect(command.slice(1)).toEqual(["localhost", "22"]);
  });
});

describe("reproCommands", () => {
  it("appends the az network bastion tunnel command for the setup-selected port", () => {
    const request = bastionRequest();

    const commands = azureBastionSshProvider.reproCommands(request, {
      sshOptions: [],
      identityFile: path.join(KEY_PATH, AD_SSH_KEY_PRIVATE),
      port: "50123",
      teardown: async () => {},
    });

    expect(commands?.join("\n")).toContain(
      `az network bastion tunnel --ids bastion-1 --target-resource-id ${request.instanceId} --resource-port 22 --port 50123 --debug`
    );
  });

  it("falls back to the default Bastion port when no additional data is present", () => {
    const request = bastionRequest();

    const commands = azureBastionSshProvider.reproCommands(request);

    expect(commands?.join("\n")).toContain("--port 50022");
  });
});

describe("generateKeys", () => {
  it("sets the subscription and mints a key + cert in a temp directory", async () => {
    const request = bastionRequest();

    await expect(
      azureBastionSshProvider.generateKeys!({} as any, request, {
        requestId: "request-1",
        debug: false,
      })
    ).resolves.toEqual({
      privateKeyPath: path.join(KEY_PATH, AD_SSH_KEY_PRIVATE),
      certificatePath: path.join(KEY_PATH, AD_CERT_FILENAME),
    });

    expect(azSetSubscription).toHaveBeenCalledWith(
      request,
      expect.objectContaining({ debug: false })
    );
  });
});

describe("setupProxy", () => {
  it("spawns the Bastion tunnel and returns its teardown and local port", async () => {
    const killTunnel = vi.fn().mockResolvedValue(undefined);
    vi.mocked(trySpawnBastionTunnel).mockResolvedValue(tunnelMeta(killTunnel));

    const request = bastionRequest();
    const result = await azureBastionSshProvider.setupProxy!(request, {
      debug: false,
      abortController: new AbortController(),
    });

    expect(result.port).toBe("50123");
    await result.teardown();
    expect(killTunnel).toHaveBeenCalled();
  });
});

describe("setup", () => {
  const setupOptions = () => ({
    requestId: "request-1",
    abortController: new AbortController(),
    debug: false,
  });

  it("mints keys, spawns the tunnel, and returns the resulting connection options", async () => {
    const request = bastionRequest();

    const result = await azureBastionSshProvider.setup!(
      {} as any,
      request,
      setupOptions()
    );

    expect(result.identityFile).toBe(path.join(KEY_PATH, AD_SSH_KEY_PRIVATE));
    expect(result.port).toBe("50123");
    expect(result.sshOptions).toEqual([
      `CertificateFile=${path.join(KEY_PATH, AD_CERT_FILENAME)}`,
      "StrictHostKeyChecking=no",
      "UserKnownHostsFile=/dev/null",
    ]);
  });

  it("tears down both the tunnel and the temp key directory", async () => {
    const killTunnel = vi.fn().mockResolvedValue(undefined);
    const cleanup = vi.fn().mockResolvedValue(undefined);
    vi.mocked(trySpawnBastionTunnel).mockResolvedValue(tunnelMeta(killTunnel));
    vi.mocked(createTempDirectoryForKeys).mockResolvedValue({
      path: KEY_PATH,
      cleanup,
    });

    const result = await azureBastionSshProvider.setup!(
      {} as any,
      bastionRequest(),
      setupOptions()
    );
    await result.teardown();

    expect(killTunnel).toHaveBeenCalled();
    expect(cleanup).toHaveBeenCalled();
  });

  it("throws when the Azure CLI login resolves to an unexpected linux user", async () => {
    vi.mocked(azSetSubscription).mockResolvedValue("someone-else@example.com");

    await expect(
      azureBastionSshProvider.setup!(
        {} as any,
        bastionRequest(),
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
      azureBastionSshProvider.setup!(
        {} as any,
        bastionRequest(),
        setupOptions()
      )
    ).rejects.toThrow();

    expect(cleanup).toHaveBeenCalled();
    expect(trySpawnBastionTunnel).not.toHaveBeenCalled();
  });
});

describe("unprovisionedAccessPatterns / provisionedAccessPatterns", () => {
  const matches = (patterns: readonly { pattern: RegExp }[], stderr: string) =>
    patterns.some((p) => p.pattern.test(stderr));

  it("retries only on the sudo propagation message", () => {
    expect(
      matches(
        azureBastionSshProvider.unprovisionedAccessPatterns,
        "Sorry, user miguel may not run sudo on my-vm."
      )
    ).toBe(true);
    expect(
      matches(
        azureBastionSshProvider.unprovisionedAccessPatterns,
        "Permission denied (publickey)."
      )
    ).toBe(false);
  });

  it("treats a sudo password prompt as evidence that sudo access has propagated", () => {
    expect(
      matches(
        azureBastionSshProvider.provisionedAccessPatterns ?? [],
        "sudo: a password is required"
      )
    ).toBe(true);
  });
});
