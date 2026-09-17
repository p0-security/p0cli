/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { promptForCredentials } from "../login-page";
import inquirer from "inquirer";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("inquirer", () => ({
  default: {
    prompt: vi.fn(),
  },
}));

describe("promptForCredentials", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns the email and password provided by the prompt", async () => {
    (inquirer.prompt as any).mockResolvedValueOnce({
      email: "user@example.com",
      password: "secret",
    });

    const result = await promptForCredentials();

    expect(result).toEqual({
      email: "user@example.com",
      password: "secret",
    });
  });

  it("prompts for an email input and a masked password", async () => {
    (inquirer.prompt as any).mockResolvedValueOnce({
      email: "user@example.com",
      password: "secret",
    });

    await promptForCredentials();

    expect(inquirer.prompt).toHaveBeenCalledTimes(1);
    const [questions] = (inquirer.prompt as any).mock.calls[0];

    expect(questions).toHaveLength(2);
    expect(questions[0]).toMatchObject({
      type: "input",
      name: "email",
    });
    expect(questions[1]).toMatchObject({
      type: "password",
      name: "password",
      mask: "*",
    });
  });
});
