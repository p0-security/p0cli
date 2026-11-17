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
  revokeRequest,
} from "../../drivers/api";
import { authenticate } from "../../drivers/auth";
import { AwsSshGenerated, AwsSshPermission } from "../../plugins/aws/types";
import { sshOrScp } from "../../plugins/ssh";
import { scpCommand } from "../scp";
import { sshCommand } from "../ssh";
import { noop } from "lodash";
import { beforeEach, describe, expect, it, vi, Mock } from "vitest";
import yargs from "yargs";

vi.mock("../../drivers/api");
vi.mock("../../drivers/auth");
vi.mock("../../drivers/stdio");
vi.mock("../../plugins/ssh");
vi.mock("../../common/keys");

const mockSshOrScp = sshOrScp as Mock;
const mockFetchCommand = fetchCommand as Mock;
const mockIntegrationConfig = fetchIntegrationConfig as Mock;
const mockFetchStreamingStatus = fetchStreamingStatus as Mock;
const mockFetchSshHostKeys = fetchSshHostKeys as Mock;
const mockRevokeRequest = revokeRequest as Mock;

const REQUEST_ID = "request-id";

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

const MOCK_RESPONSE = {
  ok: true,
  message: "a message",
  id: REQUEST_ID,
  isPreexisting: false,
  isPersistent: false,
};

describe.each([
  ["ssh", sshCommand, "ssh some-instance"],
  ["scp", scpCommand, "scp some-instance:/remote/file /local/file"],
])("%s --relinquish", (_, command, argv) => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockIntegrationConfig.mockResolvedValue({
      config: { "iam-write": { "aws:test-account": { state: "installed" } } },
    });
    mockFetchSshHostKeys.mockResolvedValue({ hostKeys: [] });
    mockFetchCommand.mockResolvedValue({
      ...MOCK_RESPONSE,
      request: { status: "NEW" },
    });
    mockFetchStreamingStatus.mockImplementation(async function* () {
      yield {
        ...MOCK_RESPONSE,
        request: {
          status: "DONE",
          id: REQUEST_ID,
          generated: MOCK_GENERATED,
          permission: MOCK_PERMISSION,
        },
      };
    });
  });

  it("relinquishes the request after the session", async () => {
    await command(yargs()).fail(noop).parse(`${argv} --relinquish`);

    expect(mockRevokeRequest).toHaveBeenCalledExactlyOnceWith(
      await authenticate(),
      REQUEST_ID,
      undefined
    );
    expect(mockSshOrScp.mock.invocationCallOrder[0]).toBeLessThan(
      mockRevokeRequest.mock.invocationCallOrder[0] as number
    );
  });

  it("leaves the request alone by default", async () => {
    await command(yargs()).fail(noop).parse(argv);

    expect(mockSshOrScp).toHaveBeenCalledOnce();
    expect(mockRevokeRequest).not.toHaveBeenCalled();
  });

  it("lets a signal interrupt the session", async () => {
    await command(yargs()).fail(noop).parse(argv);

    expect(mockSshOrScp).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ interrupted: expect.any(AbortSignal) })
    );
  });
});
