/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { TEST_PUBLIC_KEY } from "../../common/__mocks__/keys";
import {
  fetchCommand,
  fetchIntegrationConfig,
  fetchSshHostKeys,
  fetchStreamingStatus,
} from "../../drivers/api";
import { AwsSshGenerated, AwsSshPermission } from "../../plugins/aws/types";
import { sshOrScp } from "../../plugins/ssh";
import { scpCommand } from "../scp";
import { noop } from "lodash";
import { beforeEach, describe, expect, it, vi, Mock } from "vitest";
import yargs from "yargs";

vi.mock("../../drivers/api");
vi.mock("../../drivers/auth");
vi.mock("../../drivers/stdio", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../drivers/stdio")>()),
  print1: vi.fn(),
  print2: vi.fn(),
}));
vi.mock("../../plugins/ssh");
vi.mock("../../common/keys");
// The AWS CLI and Session Manager plugin aren't installed everywhere tests run
vi.mock("../../plugins/aws/ssm/install", () => ({
  ensureSsmInstall: vi.fn().mockResolvedValue(true),
}));

const mockSshOrScp = sshOrScp as Mock;
const mockFetchCommand = fetchCommand as Mock;
const mockIntegrationConfig = fetchIntegrationConfig as Mock;
const mockFetchStreamingStatus = fetchStreamingStatus as Mock;
const mockFetchSshHostKeys = fetchSshHostKeys as Mock;

const MOCK_PERMISSION: AwsSshPermission = {
  provider: "aws",
  publicKey: TEST_PUBLIC_KEY,
  region: "region",
  alias: "alias",
  resource: {
    account: "accountId",
    accountId: "accountId",
    arn: "arn",
    idcRegion: "idcRegion",
    idcId: "idcId",
    name: "name",
    userName: "userName",
    instanceId: "instanceId",
  },
};

const MOCK_GENERATED = {
  resource: {
    name: "name",
  },
  linuxUserName: "linuxUserName",
} as AwsSshGenerated;

mockIntegrationConfig.mockResolvedValue({
  config: {
    "iam-write": {
      ["aws:test-account"]: {
        state: "installed",
      },
    },
  },
});

/** Simulates a streaming response from the API for ephemeral access. */
const mockStreaming = () => {
  mockFetchCommand.mockImplementationOnce(() => ({
    ok: true,
    message: "a message",
    id: "abcefg",
    isPreexisting: false,
    isPersistent: false,
    request: { status: "NEW" },
  }));
  mockFetchStreamingStatus.mockImplementationOnce(async function* () {
    yield {
      ok: true,
      message: "Request approved",
      id: "abcefg",
      isPreexisting: false,
      isPersistent: false,
      request: {
        status: "DONE",
        id: "abcefg",
        generated: MOCK_GENERATED,
        permission: MOCK_PERMISSION,
      },
    };
  });
};

describe("scp", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchCommand.mockReset();
    mockFetchStreamingStatus.mockReset();
    mockFetchSshHostKeys.mockResolvedValue({ hostKeys: [] });
    mockStreaming();
  });

  it("should forward --duration to p0 request", async () => {
    await scpCommand(yargs())
      .fail(noop)
      .parse([
        "scp",
        "some-instance:/tmp/remote.txt",
        "./local.txt",
        "--provider",
        "aws",
        "--duration",
        "10 minutes",
      ]);
    const requestArgs = mockFetchCommand.mock.calls[0]?.[1].arguments;
    const durationIndex = requestArgs.indexOf("--duration");
    expect(durationIndex).toBeGreaterThan(-1);
    expect(requestArgs[durationIndex + 1]).toBe("10 minutes");
    expect(mockSshOrScp).toHaveBeenCalled();
  });

  it("should not send --duration without the flag", async () => {
    await scpCommand(yargs())
      .fail(noop)
      .parse([
        "scp",
        "some-instance:/tmp/remote.txt",
        "./local.txt",
        "--provider",
        "aws",
      ]);
    const requestArgs = mockFetchCommand.mock.calls[0]?.[1].arguments;
    expect(requestArgs).toContain("--public-key");
    expect(requestArgs).not.toContain("--duration");
  });
});
