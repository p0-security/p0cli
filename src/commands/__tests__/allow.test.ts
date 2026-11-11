/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchCommand } from "../../drivers/api";
import { authenticate } from "../../drivers/auth";
import { allowCommand } from "../allow";
import { beforeEach, describe, expect, it, vi, Mock } from "vitest";
import yargs from "yargs";

vi.mock("../../drivers/api");
vi.mock("../../drivers/auth", () => ({ authenticate: vi.fn() }));
vi.mock("../../drivers/stdio");

const mockFetchCommand = fetchCommand as Mock;
const mockAuthenticate = authenticate as Mock;

describe("allow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchCommand.mockResolvedValue({ ok: true, message: "a message" });
  });

  it("consumes --debug instead of forwarding it to P0", async () => {
    await allowCommand(yargs()).parse("allow gcloud role viewer --debug");
    expect(mockFetchCommand).toHaveBeenCalledWith(
      undefined,
      expect.objectContaining({ debug: true }),
      ["allow", "gcloud", "role", "viewer"]
    );
    expect(mockAuthenticate).toHaveBeenCalledWith({ debug: true });
  });

  it("consumes --debug when it comes before the arguments", async () => {
    await allowCommand(yargs()).parse("allow --debug gcloud role viewer");
    expect(mockFetchCommand).toHaveBeenCalledWith(
      undefined,
      expect.objectContaining({ debug: true }),
      ["allow", "gcloud", "role", "viewer"]
    );
  });

  it("does not set debug without --debug", async () => {
    await allowCommand(yargs()).parse("allow gcloud role viewer");
    expect(mockFetchCommand).toHaveBeenCalledWith(
      undefined,
      expect.not.objectContaining({ debug: true }),
      ["allow", "gcloud", "role", "viewer"]
    );
    expect(mockAuthenticate).toHaveBeenCalledWith({ debug: undefined });
  });

  it("forwards --help to P0", async () => {
    await allowCommand(yargs()).parse("allow --help");
    expect(mockFetchCommand).toHaveBeenCalledWith(
      undefined,
      expect.anything(),
      ["allow", "--help"]
    );
  });
});
