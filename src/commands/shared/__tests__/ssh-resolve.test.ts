/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authenticate } from "../../../drivers/auth";
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
vi.mock("../../../drivers/stdio", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../drivers/stdio")>()),
  print2: vi.fn(),
}));
vi.mock("../../../util", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../util")>()),
  getAppPath: vi.fn().mockReturnValue("/usr/local/bin/p0"),
  conditionalAbortBeforeThrow: vi.fn().mockReturnValue(vi.fn()),
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
});
