/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { decodeProvisionStatus } from "..";
import { fetchIntegrationConfig } from "../../../drivers/api";
import { Authn } from "../../../types/identity";
import { PermissionRequest } from "../../../types/request";
import { PluginSshRequest } from "../../../types/ssh";
import { request } from "../request";
import { BaseSshCommandArgs, provisionRequest } from "../ssh";
import { beforeEach, describe, expect, it, vi, Mock } from "vitest";
import yargs from "yargs";

vi.mock("../request", () => ({
  request: vi.fn(),
}));
vi.mock("../../../common/keys");
vi.mock("../../../drivers/api");
vi.mock("../../../drivers/stdio", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../drivers/stdio")>()),
  print2: vi.fn(),
}));
vi.mock("..", async (importOriginal) => ({
  ...(await importOriginal<typeof import("..")>()),
  decodeProvisionStatus: vi.fn(),
}));
vi.mock("typescript", async (importOriginal) => ({
  ...(await importOriginal<typeof import("typescript")>()),
  sys: { exit: vi.fn() },
}));

const mockInnerRequest = vi.fn();
const mockRequest = request as Mock;
const mockIntegrationConfig = fetchIntegrationConfig as Mock;
const mockDecodeProvisionStatus = decodeProvisionStatus as Mock;

const MOCK_RESPONSE = {
  ok: true,
  message: "approved",
  id: "request-123",
  isPreexisting: false,
  isPersistent: false,
  isPreapproved: false,
  request: {
    status: "DONE",
    permission: { provider: "aws" },
    generated: {},
    principal: "user@example.com",
  } as unknown as PermissionRequest<PluginSshRequest>,
};

const mockAuthn = {
  identity: { credential: { expires_at: 0 }, org: {} },
  getToken: vi.fn().mockResolvedValue("mock-token"),
} as unknown as Authn;

const baseArgs = {
  $0: "p0",
  _: ["ssh"],
} satisfies yargs.ArgumentsCamelCase<BaseSshCommandArgs>;

describe("provisionRequest", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRequest.mockReturnValue(mockInnerRequest);
    mockInnerRequest.mockResolvedValue(MOCK_RESPONSE);
    mockIntegrationConfig.mockResolvedValue({
      config: {
        "iam-write": { "aws:test-account": { state: "installed" } },
      },
    });
    mockDecodeProvisionStatus.mockResolvedValue(true);
  });

  it("should try with sudo first when approvedOnly is true even if no sudo flag", async () => {
    const args = { ...baseArgs, sudo: false };

    await provisionRequest(mockAuthn, args, "my-instance", {
      approvedOnly: true,
    });

    expect(mockInnerRequest).toHaveBeenCalledTimes(1);
    const requestArgs = mockInnerRequest.mock.calls[0]![0].arguments;
    expect(requestArgs).toContain("--sudo");
  });

  it("should retry without sudo when approvedOnly and first request fails", async () => {
    const args = { ...baseArgs, sudo: false };
    mockInnerRequest
      .mockRejectedValueOnce(new Error("no sudo access"))
      .mockResolvedValueOnce(MOCK_RESPONSE);

    await provisionRequest(mockAuthn, args, "my-instance", {
      approvedOnly: true,
    });

    expect(mockInnerRequest).toHaveBeenCalledTimes(2);
    const retryArgs = mockInnerRequest.mock.calls[1]![0].arguments;
    expect(retryArgs).not.toContain("--sudo");
  });
});
