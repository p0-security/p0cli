import { fetchCommand } from "../../drivers/api";
import { lsCommand } from "../ls";
import yargs from "yargs";

jest.mock("../../drivers/api");
jest.mock("../../drivers/auth");

const mockFetchCommand = fetchCommand as jest.Mock;
const stdout = jest.spyOn(global.console, "log");
const stderr = jest.spyOn(global.console, "error");

describe("ls", () => {
  describe("when valid ls command", () => {
    const command = "ls ssh destination";

    beforeAll(() => {
      mockFetchCommand.mockResolvedValue({
        ok: true,
        term: "",
        arg: "destination",
        items: ["instance-1", "instance-2"],
      });
    });

    it("should print list response", async () => {
      await lsCommand(yargs).parse(command);
      expect(stderr.mock.calls).toMatchSnapshot();
      expect(stdout.mock.calls).toMatchSnapshot();
    });
  });

  describe("when error", () => {
    const command = "ls foo";

    beforeAll(() => {
      mockFetchCommand.mockResolvedValue({
        error: `p0 ls

List available resources

Commands:
  p0 ls ssh <destination>  Secure Shell (SSH) session

Options:
  --help  Show help                                                    [boolean]

Unknown argument: foo`,
      });
    });

    it("should print error message", async () => {
      let error: any;
      try {
        await lsCommand(yargs)
          .fail((_, err) => (error = err))
          .parse(command);
      } catch (thrown: any) {
        error = thrown;
      }
      expect(error).toMatchSnapshot();
    });
  });
});
