/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import * as auth from "../../drivers/auth";
import { print1, print2 } from "../../drivers/stdio";
import { printBearerToken } from "../print-bearer-token";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../drivers/stdio");
vi.mock("../../drivers/auth");

describe("print-bearer-token", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("prints the token when one is present", async () => {
    // Mock authenticate() to return an object with getToken()
    const mockAuthn = { getToken: vi.fn().mockResolvedValue("test-token") };
    vi.spyOn(auth as any, "authenticate").mockResolvedValueOnce(
      mockAuthn as any
    );

    await printBearerToken();

    expect(print1).toHaveBeenCalledWith("test-token");
  });

  it("prints an error and exits when token is missing", async () => {
    const mockAuthn = { getToken: vi.fn().mockResolvedValue(undefined) };
    vi.spyOn(auth as any, "authenticate").mockResolvedValueOnce(
      mockAuthn as any
    );

    // Prevent actual process.exit from killing the test runner
    vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`process.exit:${code}`);
    }) as unknown as typeof process.exit);

    await expect(printBearerToken()).rejects.toThrow("process.exit:1");

    expect(print2).toHaveBeenCalledWith("No access token found in identity.");
  });
});
