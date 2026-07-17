/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authenticate } from "../../../drivers/auth";
import { awsSshProvider } from "../../../plugins/aws/ssh";
import { TARGET_CONNECT_TIMEOUT_SECONDS } from "../../../plugins/azure/ssh-jump-host";
import { Authn } from "../../../types/identity";
import { sshResolveAction } from "../../ssh-resolve";
import { SshResolveCommandArgs } from "../ssh";
import { prepareRequest } from "../ssh";
import fs from "fs";
import { beforeEach, describe, expect, it, vi, Mock } from "vitest";
import yargs from "yargs";

vi.mock("../../../drivers/auth", () => ({
  authenticate: vi.fn(),
}));
// The azure jump-host provider's generateKeys shells out to the Azure CLI;
// stub the login boundary and pin the temp key directory.
vi.mock("../../../plugins/azure/auth", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../plugins/azure/auth")>()),
  azSetSubscription: vi.fn(async () => "testuser"),
}));
vi.mock("../../../plugins/ssh/shared", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../plugins/ssh/shared")>()),
  createTempDirectoryForKeys: vi.fn(async () => ({
    path: "/tmp/azure",
    cleanup: async () => {},
  })),
}));
vi.mock("../../../drivers/stdio", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../drivers/stdio")>()),
  print2: vi.fn(),
}));
vi.mock("../../../util", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../util")>()),
  getAppPath: vi.fn().mockReturnValue("/usr/local/bin/p0"),
  conditionalAbortBeforeThrow: vi.fn().mockReturnValue(vi.fn()),
  // Stubs the `az ssh cert` subprocess run by the azure jump-host generateKeys
  exec: vi.fn(async () => ({ stdout: "", stderr: "" })),
}));
vi.mock("../ssh", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../ssh")>()),
  prepareRequest: vi.fn(),
}));
vi.mock("../ssh-cleanup", () => ({
  cleanupStaleSshConfigs: vi.fn(),
}));
vi.mock("tmp-promise", () => ({
  default: { fileSync: vi.fn().mockReturnValue({ name: "/tmp/req.json" }) },
}));
vi.mock("typescript", async (importOriginal) => ({
  ...(await importOriginal<typeof import("typescript")>()),
  sys: { exit: vi.fn() },
}));

const mockAuthenticate = authenticate as Mock;
const mockPrepareRequest = prepareRequest as Mock;

const mockAuthn = {
  identity: { credential: { expires_at: 0 }, org: {} },
  getToken: vi.fn().mockResolvedValue("mock-token"),
} as unknown as Authn;

const basePrepareResult = {
  request: { linuxUserName: "testuser", id: "req-123" },
  requestId: "req-123",
  provisionedRequest: {
    permission: { provider: "aws", resource: {} },
  },
  sshHostKeys: undefined,
  sshProvider: {
    generateKeys: vi.fn(async () => ({ privateKeyPath: "/tmp/key" })),
  },
};

const baseArgs = {
  $0: "p0",
  _: ["ssh-resolve"],
  destination: "my-instance",
  arguments: [],
} satisfies yargs.ArgumentsCamelCase<SshResolveCommandArgs>;

describe("sshResolveAction", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.P0_ORG;
    mockAuthenticate.mockResolvedValue(mockAuthn);
    mockPrepareRequest.mockResolvedValue(basePrepareResult);
    vi.spyOn(fs, "writeFileSync").mockImplementation(() => {});
    vi.spyOn(fs.promises, "mkdir").mockResolvedValue(undefined);
  });

  it("includes --org flag in ProxyCommand when P0_ORG is set", async () => {
    process.env.P0_ORG = "my-org";

    await sshResolveAction({ ...baseArgs });

    const configWriteCall = (fs.writeFileSync as Mock).mock.calls.find(
      ([path]) => typeof path === "string" && path.endsWith(".config")
    );
    expect(configWriteCall).toBeDefined();
    const configContent = configWriteCall![1] as string;
    expect(configContent).toContain("--org my-org");
  });

  it("does not include --org flag in ProxyCommand when P0_ORG is not set", async () => {
    await sshResolveAction({ ...baseArgs });

    const configWriteCall = (fs.writeFileSync as Mock).mock.calls.find(
      ([path]) => typeof path === "string" && path.endsWith(".config")
    );
    expect(configWriteCall).toBeDefined();
    const configContent = configWriteCall![1] as string;
    expect(configContent).not.toContain("--org");
  });

  it("includes ConnectTimeout when the provider sets sshConnectTimeoutSeconds", async () => {
    const originalTimeout = awsSshProvider.sshConnectTimeoutSeconds;
    awsSshProvider.sshConnectTimeoutSeconds = 10;
    try {
      await sshResolveAction({ ...baseArgs });

      const configWriteCall = (fs.writeFileSync as Mock).mock.calls.find(
        ([path]) => typeof path === "string" && path.endsWith(".config")
      );
      expect(configWriteCall).toBeDefined();
      const configContent = configWriteCall![1] as string;
      expect(configContent).toContain("ConnectTimeout 10");
    } finally {
      if (originalTimeout === undefined) {
        delete awsSshProvider.sshConnectTimeoutSeconds;
      } else {
        awsSshProvider.sshConnectTimeoutSeconds = originalTimeout;
      }
    }
  });

  it.each([-5, 0, 2.5, NaN])(
    "omits ConnectTimeout when the provider sets an invalid sshConnectTimeoutSeconds (%s)",
    async (invalidTimeout) => {
      const originalTimeout = awsSshProvider.sshConnectTimeoutSeconds;
      awsSshProvider.sshConnectTimeoutSeconds = invalidTimeout;
      try {
        await sshResolveAction({ ...baseArgs });

        const configWriteCall = (fs.writeFileSync as Mock).mock.calls.find(
          ([path]) => typeof path === "string" && path.endsWith(".config")
        );
        expect(configWriteCall).toBeDefined();
        const configContent = configWriteCall![1] as string;
        expect(configContent).not.toContain("ConnectTimeout");
      } finally {
        if (originalTimeout === undefined) {
          delete awsSshProvider.sshConnectTimeoutSeconds;
        } else {
          awsSshProvider.sshConnectTimeoutSeconds = originalTimeout;
        }
      }
    }
  );

  it("emits ConnectTimeout and the minted keys for an azure jump-host request, via the real provider", async () => {
    mockPrepareRequest.mockResolvedValue({
      ...basePrepareResult,
      provisionedRequest: {
        permission: {
          provider: "azure",
          jumpHost: {
            id: "jump-1",
            roleId: "jrole-1",
            publicIp: "4.154.21.27",
          },
          resource: { subscriptionId: "sub-1" },
        },
      },
    });

    await sshResolveAction({ ...baseArgs });

    const configWriteCall = (fs.writeFileSync as Mock).mock.calls.find(
      ([path]) => typeof path === "string" && path.endsWith(".config")
    );
    expect(configWriteCall).toBeDefined();
    const configContent = configWriteCall![1] as string;
    expect(configContent).toContain(
      `ConnectTimeout ${TARGET_CONNECT_TIMEOUT_SECONDS}`
    );
    expect(configContent).toContain("IdentityFile /tmp/azure/id_rsa");
    expect(configContent).toContain(
      "CertificateFile /tmp/azure/p0cli-azure-ad-ssh-cert.pub"
    );
  });

  it("omits ConnectTimeout when the provider does not set sshConnectTimeoutSeconds", async () => {
    await sshResolveAction({ ...baseArgs });

    const configWriteCall = (fs.writeFileSync as Mock).mock.calls.find(
      ([path]) => typeof path === "string" && path.endsWith(".config")
    );
    expect(configWriteCall).toBeDefined();
    const configContent = configWriteCall![1] as string;
    expect(configContent).not.toContain("ConnectTimeout");
  });
});
