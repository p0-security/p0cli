/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchCommand } from "../../drivers/api";
import { print1, print2 } from "../../drivers/stdio";
import { grantCommand } from "../grant";
import yargs from "yargs";

jest.mock("../../drivers/api");
jest.mock("../../drivers/auth");
jest.mock("../../drivers/auth/path");
jest.mock("../../drivers/stdio");

const mockFetchCommand = fetchCommand as jest.Mock;
const mockPrint1 = print1 as jest.Mock;
const mockPrint2 = print2 as jest.Mock;

describe("grant", () => {
  beforeEach(() => jest.clearAllMocks());

  describe("when valid grant command", () => {
    const command =
      "grant gcloud role viewer --to someone@test.com --principal-type user";

    function mockFetch() {
      mockFetchCommand.mockResolvedValue({
        ok: true,
        message: "a message",
        id: "abcefg",
        isPreexisting: false,
        isPersistent: false,
      });
    }

    it(`should print request response`, async () => {
      mockFetch();
      await grantCommand(yargs()).parse(command);
      expect(mockPrint2.mock.calls).toMatchSnapshot();
      expect(mockPrint1).not.toHaveBeenCalled();
    });
  });
});
