/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchCommand, fetchStreamingCommand } from "../../drivers/api";
import { print1, print2 } from "../../drivers/stdio";
import { failure } from "../../testing/yargs";
import { RequestResponse } from "../../types/request";
import { sleep } from "../../util";
import { requestCommand } from "../request";
import yargs from "yargs";

jest.mock("../../drivers/api", () => ({
  ...jest.requireActual("../../drivers/api"),
  fetchCommand: jest.fn(),
  fetchStreamingCommand: jest.fn(), // Add this
  streamingApiFetch: jest.fn(),
}));
jest.mock("../../drivers/auth");
jest.mock("../../drivers/stdio", () => ({
  ...jest.requireActual("../../drivers/stdio"),
  print1: jest.fn(),
  print2: jest.fn(),
}));

const mockFetchCommand = fetchCommand as jest.Mock;
const mockFetchStreamingCommand = fetchStreamingCommand as jest.Mock;
const mockPrint1 = print1 as jest.Mock;
const mockPrint2 = print2 as jest.Mock;

describe("request", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("when valid request command", () => {
    const command = "request gcloud role viewer";

    function mockFetch(response?: Partial<RequestResponse<unknown>>) {
      mockFetchCommand.mockResolvedValue({
        ok: true,
        message: "a message",
        id: "abcefg",
        isPreexisting: false,
        isPersistent: false,
        ...(response ?? {}),
      });
    }

    describe.each([
      [false, false, true],
      [true, false, true],
      [false, true, true],
    ])(
      "preexisting=%p persistent=%p",
      (isPreexisting, isPersistent, should) => {
        it(`should${should ? "" : " not"} print request response`, async () => {
          mockFetch({ isPreexisting, isPersistent });
          await requestCommand(yargs()).parse(command);
          expect(mockPrint2.mock.calls).toMatchSnapshot();
          expect(mockPrint1).not.toHaveBeenCalled();
        });
      }
    );

    it("should wait for access", async () => {
      /**
       * This test checks that the request command waits for access to be granted
       * before resolving the promise.
       */
      mockFetchStreamingCommand.mockImplementation(async function* () {
        yield {
          ok: true,
          message: "a message",
          id: "abcefg",
          isPreexisting: false,
          isPersistent: false,
          request: { status: "NEW" },
        };
        await sleep(200);
        yield {
          ok: true,
          message: "Request approved",
          id: "abcefg",
          isPreexisting: false,
          isPersistent: false,
          request: { status: "DONE" },
        };
      });
      const promise = requestCommand(yargs()).parse(`${command} --wait`);
      // await for the first response to yield
      const wait = sleep(100);
      await expect(wait).resolves.toBeUndefined();
      await expect(promise).resolves.toBeDefined();
      expect(mockPrint2.mock.calls).toMatchSnapshot();
      expect(mockPrint1).not.toHaveBeenCalled();
    });
  });

  describe("when error", () => {
    const command = "request foo";

    beforeAll(() => {
      mockFetchCommand.mockResolvedValue({
        error: `p0 request

Request access to a resource using P0

Commands:
  p0 request gcloud             Google Cloud

Options:
      --help    Show help                                              [boolean]
      --reason  Reason access is needed                                 [string]
  -w, --wait    Block until the request is completed                   [boolean]

Unknown argument: foo`,
      });
    });

    it("should print error message", async () => {
      const error = await failure(requestCommand(yargs()), command);
      expect(error).toMatchSnapshot();
    });

    it("should handle stream errors", async () => {
      mockFetchStreamingCommand.mockImplementation(async function* () {
        yield {
          ok: true,
          message: "a message",
          id: "abcefg",
          isPreexisting: false,
          isPersistent: false,
          request: { status: "NEW" },
        };
        await sleep(200);
        throw new TypeError("terminated");
      });
      const command = "request gcloud role viewer --wait";
      const error = await failure(requestCommand(yargs()), command);
      expect(error).toMatchSnapshot();
    });
  });
});
