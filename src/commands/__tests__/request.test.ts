import { fetchCommand } from "../../drivers/api";
import { RequestResponse } from "../../types/request";
import { sleep } from "../../util";
import { requestCommand } from "../request";
import { onSnapshot } from "firebase/firestore";
import yargs from "yargs";

jest.mock("../../drivers/api");
jest.mock("../../drivers/auth");

const mockFetchCommand = fetchCommand as jest.Mock;
const stdout = jest.spyOn(global.console, "log");
const stderr = jest.spyOn(global.console, "error");

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
          await requestCommand(yargs).parse(command);
          expect(stderr.mock.calls).toMatchSnapshot();
          expect(stdout).not.toHaveBeenCalled();
        });
      }
    );

    it("should wait for access", async () => {
      mockFetch();
      const promise = requestCommand(yargs).parse(`${command} --wait`);
      const wait = sleep(10);
      await expect(wait).resolves.toBeUndefined();
      (onSnapshot as any).trigger({
        status: "DONE",
      });
      await expect(promise).resolves.toBeDefined();
      expect(stderr.mock.calls).toMatchSnapshot();
      expect(stdout).not.toHaveBeenCalled();
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
      let error: any;
      try {
        await requestCommand(yargs)
          .fail((_, err) => (error = err))
          .parse(command);
      } catch (thrown: any) {
        error = thrown;
      }
      expect(error).toMatchSnapshot();
    });
  });
});
