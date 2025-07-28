/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { TEST_PUBLIC_KEY } from "../../common/__mocks__/keys";
import {
  fetchIntegrationConfig,
  fetchStreamingCommand,
} from "../../drivers/api";
import { print1, print2 } from "../../drivers/stdio";
import { AwsSshGenerated, AwsSshPermission } from "../../plugins/aws/types";
import { sshOrScp } from "../../plugins/ssh";
import { sleep } from "../../util";
import { sshCommand } from "../ssh";
import { noop, omit } from "lodash";
import yargs from "yargs";

jest.mock("../../drivers/api");
jest.mock("../../drivers/auth");
jest.mock("../../drivers/stdio", () => ({
  ...jest.requireActual("../../drivers/stdio"),
  print1: jest.fn(),
  print2: jest.fn(),
}));
jest.mock("../../plugins/ssh");
jest.mock("../../common/keys");

const mockSshOrScp = sshOrScp as jest.Mock;
const mockPrint1 = print1 as jest.Mock;
const mockPrint2 = print2 as jest.Mock;
const mockIntegrationConfig = fetchIntegrationConfig as jest.Mock;
const mockFetchStreamingCommand = fetchStreamingCommand as jest.Mock;

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

const MOCK_REQUEST = {
  status: "DONE",
  generated: MOCK_GENERATED,
  permission: MOCK_PERMISSION,
};

mockIntegrationConfig.mockResolvedValue({
  config: {
    "iam-write": {
      ["aws:test-account"]: {
        state: "installed",
      },
    },
  },
});

describe("ssh", () => {
  const mockStreaming = (
    isPersistent: boolean,
    sleep?: () => Promise<void>
  ) => {
    mockFetchStreamingCommand.mockImplementationOnce(async function* () {
      yield {
        ok: true,
        message: "a message",
        id: "abcefg",
        isPreexisting: false,
        isPersistent,
        request: { status: "NEW" },
      };
      await sleep?.();
      yield {
        ok: true,
        message: "Request approved",
        id: "abcefg",
        isPreexisting: false,
        isPersistent,
        request: {
          status: "DONE",
          id: "abcefg",
          generated: MOCK_GENERATED,
          permission: MOCK_PERMISSION,
        },
      };
    });
  };
  describe.each([
    ["persistent", true],
    ["ephemeral", false],
  ])("%s access", (_, isPersistent) => {
    beforeEach(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      mockFetchStreamingCommand.mockReset();
    });
    it("should call p0 request with reason arg", async () => {
      mockStreaming(isPersistent);
      const promise = sshCommand(yargs())
        .fail(noop)
        .parse(`ssh some-instance --reason reason --provider aws`);
      await sleep(10);
      const hiddenFilenameRequestArgs = omit(
        mockFetchStreamingCommand.mock.calls[0][1],
        "$0"
      );
      expect(hiddenFilenameRequestArgs).toMatchSnapshot("args");
      await expect(promise).resolves.toBeDefined();
    });

    it("should wait for access grant/provisioning", async () => {
      mockStreaming(isPersistent, async () => await sleep(200));
      const promise = sshCommand(yargs()).fail(noop).parse(`ssh some-instance`);
      const wait = sleep(100);
      await Promise.race([wait, promise]);
      await expect(wait).resolves.toBeUndefined();
      await expect(promise).resolves.toBeDefined();
    });
    it("should call sshOrScp with non-interactive command", async () => {
      mockStreaming(isPersistent);
      const promise = sshCommand(yargs())
        .fail(noop)
        .parse(`ssh some-instance do something`);
      await expect(promise).resolves.toBeDefined();
      expect(mockPrint2.mock.calls).toMatchSnapshot("stderr");
      expect(mockPrint1).not.toHaveBeenCalled();
      expect(mockSshOrScp).toHaveBeenCalled();
    });

    it("should call sshOrScp with interactive session", async () => {
      mockStreaming(isPersistent);
      const promise = sshCommand(yargs()).fail(noop).parse(`ssh some-instance`);
      await expect(promise).resolves.toBeDefined();
      expect(mockPrint2.mock.calls).toMatchSnapshot("stderr");
      expect(mockPrint1).not.toHaveBeenCalled();
      expect(mockSshOrScp).toHaveBeenCalled();
    });
  });
});
