import { fetchCommand } from "../../drivers/api";
import { print1, print2 } from "../../drivers/stdio";
import { failure } from "../../testing/yargs";
import { RequestResponse } from "../../types/request";
import { sleep } from "../../util";
import { requestCommand } from "../request";
import { onSnapshot } from "firebase/firestore";
import yargs from "yargs";

jest.mock("../../drivers/api");
jest.mock("../../drivers/auth");
jest.mock("../../drivers/stdio");

const mockFetchCommand = fetchCommand as jest.Mock;
const mockPrint1 = print1 as jest.Mock;
const mockPrint2 = print2 as jest.Mock;

describe("request", () => {
  beforeEach(() => jest.clearAllMocks());

  describe("when valid request command", () => {
    const command = "request gcloud role viewer";

    function mockFetch(response?: Partial<RequestResponse>) {
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
      mockFetch();
      const promise = requestCommand(yargs()).parse(`${command} --wait`);
      const wait = sleep(10);
      await expect(wait).resolves.toBeUndefined();
      (onSnapshot as any).trigger({
        status: "DONE",
      });
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
  });
});
