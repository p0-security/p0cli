/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchAdminLsCommand, fetchCommand } from "../../drivers/api";
import { print1, print2 } from "../../drivers/stdio";
import { failure } from "../../testing/yargs";
import { lsCommand } from "../ls";
import { beforeAll, beforeEach, describe, expect, it, vi, Mock } from "vitest";
import yargs from "yargs";

vi.mock("../../drivers/api");
vi.mock("../../drivers/auth");
vi.mock("../../drivers/stdio");
vi.spyOn(process, "exit");

const mockFetchCommand = fetchCommand as Mock;
const mockFetchAdminLsCommand = fetchAdminLsCommand as Mock;
const mockPrint1 = print1 as Mock;
const mockPrint2 = print2 as Mock;

const ITEMS = [
  { key: "instance-1", group: "Group", value: "Resource 1" },
  { key: "instance-2", value: "Resource 2" },
];

describe("ls", () => {
  const mockItems = (items: object[]) =>
    mockFetchCommand.mockResolvedValue({
      ok: true,
      term: "",
      arg: "destination",
      items,
    });

  const mockAdminItems = (items: object[]) =>
    mockFetchAdminLsCommand.mockResolvedValue({
      ok: true,
      term: "",
      arg: "destination",
      items,
    });

  beforeEach(() => vi.clearAllMocks());

  describe("when valid ls command", () => {
    const command = "ls ssh destination";

    it("should print list response", async () => {
      mockItems(ITEMS);
      await lsCommand(yargs()).exitProcess(false).parse(command);
      expect(mockPrint1.mock.calls).toMatchSnapshot("stdout");
      expect(mockPrint2.mock.calls).toMatchSnapshot("stderr");
    });

    it("should print friendly message if no items", async () => {
      mockItems([]);
      await lsCommand(yargs()).exitProcess(false).parse(command);
      expect(mockPrint1.mock.calls).toMatchSnapshot("stdout");
      expect(mockPrint2.mock.calls).toMatchSnapshot("stderr");
    });
  });

  describe("when --principal flag is used", () => {
    it.each([
      {
        description: "unquoted",
        command: "ls ssh destination --principal alice@example.com",
      },
      {
        description: "double-quoted",
        command: 'ls ssh destination --principal "alice@example.com"',
      },
      {
        description: "single-quoted",
        command: "ls ssh destination --principal 'alice@example.com'",
      },
      {
        description: "double-quoted with space",
        command: 'ls ssh destination --principal "alice @example.com"',
      },
    ])(
      "should print list response with principal in message ($description)",
      async ({ command }) => {
        mockAdminItems(ITEMS);
        await lsCommand(yargs()).exitProcess(false).parse(command);
        expect(mockPrint1.mock.calls).toMatchSnapshot("stdout");
        expect(mockPrint2.mock.calls).toMatchSnapshot("stderr");
      }
    );
  });

  describe("when --all flag is used", () => {
    const command = "ls ssh destination --all";

    it("should print list response with no indication of who can access", async () => {
      mockAdminItems(ITEMS);
      await lsCommand(yargs()).exitProcess(false).parse(command);
      expect(mockPrint1.mock.calls).toMatchSnapshot("stdout");
      expect(mockPrint2.mock.calls).toMatchSnapshot("stderr");
    });
  });

  describe("when --json flag is used", () => {
    const makeItems = (count: number) =>
      Array.from({ length: count }, (_, i) => ({
        key: `instance-${i + 1}`,
        value: `Resource ${i + 1}`,
      }));

    const parseJsonOutput = () => {
      expect(mockPrint1).toHaveBeenCalledTimes(1);
      return JSON.parse(mockPrint1.mock.calls[0]![0]);
    };

    it("should truncate items to the requested --size", async () => {
      const items = makeItems(10);
      mockItems(items);
      await lsCommand(yargs())
        .exitProcess(false)
        .parse("ls ssh destination --json --size 3");

      const parsed = parseJsonOutput();
      expect(parsed.ok).toBe(true);
      expect(parsed.term).toBe("");
      expect(parsed.arg).toBe("destination");
      expect(parsed.items).toEqual(items.slice(0, 3));
      expect(mockPrint2).not.toHaveBeenCalled();
    });

    it("should cap items at the default size (15) when --size is omitted", async () => {
      mockItems(makeItems(20));
      await lsCommand(yargs())
        .exitProcess(false)
        .parse("ls ssh destination --json");

      const parsed = parseJsonOutput();
      expect(parsed.items).toHaveLength(15);
    });

    it("should request double the requested size from the backend", async () => {
      mockItems(makeItems(10));
      await lsCommand(yargs())
        .exitProcess(false)
        .parse("ls ssh destination --json --size 4");

      expect(mockFetchCommand).toHaveBeenCalledTimes(1);
      const allArguments = mockFetchCommand.mock.calls[0]![2];
      const sizeIdx = allArguments.indexOf("--size");
      expect(sizeIdx).toBeGreaterThanOrEqual(0);
      expect(allArguments[sizeIdx + 1]).toBe("8");
    });

    it("should not pad items when fewer items than --size are returned", async () => {
      const items = makeItems(2);
      mockItems(items);
      await lsCommand(yargs())
        .exitProcess(false)
        .parse("ls ssh destination --json --size 10");

      const parsed = parseJsonOutput();
      expect(parsed.items).toEqual(items);
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
      const error = await failure(
        lsCommand(yargs().exitProcess(false)),
        command
      );
      expect(error).toMatchSnapshot();
    });
  });
});
