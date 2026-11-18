/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print1 } from "../../../drivers/stdio";
import { gitConfigEntries, gitInstall } from "../install";
import { SERVER } from "./fixtures";
import { execFileSync } from "node:child_process";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../drivers/stdio");

beforeEach(() => {
  vi.clearAllMocks();
});

describe("git install", () => {
  it("sends HTTPS and SSH github.com remotes to the gateway", () => {
    expect(gitConfigEntries(`${SERVER}/`)).toEqual([
      { key: `url.${SERVER}/git/.insteadOf`, value: "https://github.com/" },
      { key: `url.${SERVER}/git/.insteadOf`, value: "http://github.com/" },
      { key: `url.${SERVER}/git/.insteadOf`, value: "git://github.com/" },
      { key: `url.${SERVER}/git/.insteadOf`, value: "git@github.com:" },
      { key: `url.${SERVER}/git/.insteadOf`, value: "ssh://git@github.com/" },
      { key: `url.${SERVER}/git/.insteadOf`, value: "ssh://github.com/" },
      { key: "credential.https://gateway.example.com.helper", value: "" },
      {
        key: "credential.https://gateway.example.com.helper",
        value: "!p0 git credential",
      },
      {
        key: "credential.https://gateway.example.com.useHttpPath",
        value: "true",
      },
    ]);
  });

  it("prints variables that git reads", async () => {
    await gitInstall({ serverUrl: SERVER, global: false, json: false });
    const exports = String(vi.mocked(print1).mock.calls[0]?.[0]);

    const resolved = (url: string) =>
      execFileSync(
        "sh",
        ["-c", `${exports}\ngit ls-remote --get-url "$0"`, url],
        {
          encoding: "utf-8",
          env: { PATH: process.env.PATH, HOME: "/nonexistent" },
        }
      ).trim();

    expect(resolved("https://github.com/dunder-mifflin/scranton.git")).toBe(
      `${SERVER}/git/dunder-mifflin/scranton.git`
    );
    expect(resolved("git@github.com:dunder-mifflin/scranton.git")).toBe(
      `${SERVER}/git/dunder-mifflin/scranton.git`
    );
    for (const url of [
      "ssh://git@github.com/dunder-mifflin/scranton",
      "ssh://github.com/dunder-mifflin/scranton",
      "git://github.com/dunder-mifflin/scranton",
      "http://github.com/dunder-mifflin/scranton",
    ]) {
      expect(resolved(url)).toBe(`${SERVER}/git/dunder-mifflin/scranton`);
    }
  });

  it("prints JSON for an env setting", async () => {
    await gitInstall({ serverUrl: SERVER, global: false, json: true });

    expect(
      JSON.parse(String(vi.mocked(print1).mock.calls[0]?.[0]))
    ).toMatchObject({
      GIT_CONFIG_COUNT: "9",
      GIT_CONFIG_KEY_7: "credential.https://gateway.example.com.helper",
      GIT_CONFIG_VALUE_7: "!p0 git credential",
    });
  });
});
