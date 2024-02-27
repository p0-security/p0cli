/** Copyright © 2024-present P0 Security

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchCommand } from "../../drivers/api";
import { print1, print2 } from "../../drivers/stdio";
import { ssm } from "../../plugins/aws/ssm";
import { mockGetDoc } from "../../testing/firestore";
import { sleep } from "../../util";
import { sshCommand } from "../ssh";
import { onSnapshot } from "firebase/firestore";
import yargs from "yargs";

jest.mock("../../drivers/api");
jest.mock("../../drivers/auth");
jest.mock("../../drivers/stdio");
jest.mock("../../plugins/aws/ssm");

const mockFetchCommand = fetchCommand as jest.Mock;
const mockSsm = ssm as jest.Mock;
const mockPrint1 = print1 as jest.Mock;
const mockPrint2 = print2 as jest.Mock;

mockGetDoc({
  workflows: {
    items: [
      {
        identifier: "test-account",
        state: "installed",
        type: "aws",
      },
    ],
  },
});

mockSsm.mockResolvedValue({});

describe("ssh", () => {
  describe.each([
    ["persistent", true],
    ["ephemeral", false],
  ])("%s access", (_, isPersistent) => {
    beforeEach(() => {
      jest.clearAllMocks();
      mockFetchCommand.mockResolvedValue({
        ok: true,
        message: "a message",
        id: "abcefg",
        isPreexisting: false,
        isPersistent,
      });
    });

    it("should wait for access grant", async () => {
      const promise = sshCommand(yargs()).parse(`ssh some-instance`);
      const wait = sleep(100);
      await Promise.race([wait, promise]);
      await expect(wait).resolves.toBeUndefined();
    });

    it("should wait for provisioning", async () => {
      const promise = sshCommand(yargs()).parse(`ssh some-instance`);
      await sleep(100); // Need to wait for listen before trigger in tests
      (onSnapshot as any).trigger({
        status: "APPROVED",
      });
      const wait = sleep(100);
      await Promise.race([wait, promise]);
      await expect(wait).resolves.toBeUndefined();
    });

    it("should call ssm", async () => {
      const promise = sshCommand(yargs()).parse(`ssh some-instance`);
      await sleep(100); // Need to wait for listen before trigger in tests
      (onSnapshot as any).trigger({
        status: "APPROVED",
      });
      await sleep(100); // Need to wait for listen before trigger in tests
      (onSnapshot as any).trigger({
        status: "DONE",
      });
      await expect(promise).resolves.toBeDefined();
      expect(mockPrint2.mock.calls).toMatchSnapshot("stderr");
      expect(mockPrint1).not.toHaveBeenCalled();
      expect(mockSsm).toHaveBeenCalled();
    });
  });
});
