/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print1, print2 } from "../../../drivers/stdio";
import { SESSION_ENDED_TEXT, gitCredential } from "../credential";
import { GitStore, claimKey, readStore, updateStore } from "../store";
import {
  SERVER,
  TOKEN_ENDPOINT,
  accessTokenFor,
  jsonResponse,
  makeTempDir,
  session,
  tokenReply,
} from "./fixtures";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const paths = vi.hoisted(() => ({ p0: "" }));

vi.mock("../../../drivers/stdio");
vi.mock("../../../util", async (importOriginal) => ({
  ...(await importOriginal<object>()),
  get P0_PATH() {
    return paths.p0;
  },
}));

const fetchMock = vi.fn<typeof fetch>();

const request = (repository: string, authtype = true) =>
  [
    ...(authtype ? ["capability[]=authtype"] : []),
    "protocol=https",
    "host=gateway.example.com",
    `path=mcps/github/git/${repository}`,
    "",
  ].join("\n");

const seed = (store: Partial<GitStore>) =>
  updateStore((current) => {
    Object.assign(current, store);
  });

const replyOf = () => {
  const lines = vi.mocked(print1).mock.calls.at(-1)?.[0] as string | undefined;
  return Object.fromEntries(
    (lines ?? "").split("\n").map((line) => line.split(/=(.*)/s).slice(0, 2))
  );
};

beforeEach(async () => {
  paths.p0 = await makeTempDir();
  vi.clearAllMocks();
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("git credential get", () => {
  it("gives a Bearer token when git announces authtype", async () => {
    await seed({ sessions: { a: session("a") }, fallback: { [SERVER]: "a" } });

    await gitCredential("get", request("dunder-mifflin/scranton.git"));

    expect(replyOf()).toMatchObject({
      "capability[]": "authtype",
      authtype: "Bearer",
      credential: accessTokenFor("a"),
      ephemeral: "1",
    });
    expect(Number(replyOf().password_expiry_utc)).toBeGreaterThan(
      Date.now() / 1000
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("gives Basic credentials to an older git", async () => {
    await seed({ sessions: { a: session("a") }, fallback: { [SERVER]: "a" } });

    await gitCredential("get", request("dunder-mifflin/scranton", false));

    expect(replyOf()).toMatchObject({
      username: "p0",
      password: accessTokenFor("a"),
    });
    expect(replyOf()).not.toHaveProperty("authtype");
  });

  it("uses the Session that claims the repository, else the fallback", async () => {
    await seed({
      sessions: { a: session("a"), b: session("b") },
      claims: { [claimKey(SERVER, "Dunder-Mifflin/Scranton")]: "a" },
      fallback: { [SERVER]: "b" },
    });

    await gitCredential("get", request("dunder-mifflin/scranton.git"));
    expect(replyOf().credential).toBe(accessTokenFor("a"));

    await gitCredential("get", request("dunder-mifflin/stamford.git"));
    expect(replyOf().credential).toBe(accessTokenFor("b"));
  });

  it("refreshes once for parallel git processes", async () => {
    await seed({
      sessions: { a: session("a", { accessExpiresAt: Date.now() + 1_000 }) },
      fallback: { [SERVER]: "a" },
    });
    fetchMock.mockImplementation(async () => tokenReply("a", 1));

    await Promise.all(
      Array.from({ length: 8 }, () =>
        gitCredential("get", request("dunder-mifflin/scranton.git"))
      )
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe(TOKEN_ENDPOINT);
    expect(Object.fromEntries(new URLSearchParams(String(init?.body)))).toEqual(
      {
        grant_type: "refresh_token",
        refresh_token: "refresh-a",
        client_id: "p0-git",
      }
    );
    const credentials = vi
      .mocked(print1)
      .mock.calls.map(([lines]) => String(lines));
    expect(credentials).toHaveLength(8);
    expect(
      credentials.every((lines) => lines.includes(accessTokenFor("a", 1)))
    ).toBe(true);
    expect((await readStore()).sessions.a?.refreshToken).toBe("refresh-a-1");
  });

  it("ends the Session when the refresh token is refused", async () => {
    await seed({
      sessions: { a: session("a", { accessExpiresAt: 0 }) },
      fallback: { [SERVER]: "a" },
    });
    fetchMock.mockResolvedValue(jsonResponse({ error: "invalid_grant" }, 400));

    await gitCredential("get", request("dunder-mifflin/scranton.git"));

    expect(print1).not.toHaveBeenCalled();
    expect(print2).toHaveBeenCalledWith(SESSION_ENDED_TEXT);
    expect(await readStore()).toEqual({
      sessions: {},
      claims: {},
      fallback: {},
    });
  });

  it("keeps the Session when the refresh fails for another reason", async () => {
    await seed({
      sessions: { a: session("a", { accessExpiresAt: 0 }) },
      fallback: { [SERVER]: "a" },
    });
    fetchMock.mockResolvedValue(jsonResponse({ error: "server_error" }, 503));

    await expect(
      gitCredential("get", request("dunder-mifflin/scranton.git"))
    ).rejects.toMatch("refused the token request (503)");
    expect((await readStore()).sessions.a).toBeDefined();
  });

  it("says the Session ended when there is none", async () => {
    await gitCredential("get", request("dunder-mifflin/scranton.git"));

    expect(print1).not.toHaveBeenCalled();
    expect(print2).toHaveBeenCalledWith(SESSION_ENDED_TEXT);
  });

  it("gives nothing for a URL that is not a P0 git route", async () => {
    await gitCredential(
      "get",
      "protocol=https\nhost=github.com\npath=dunder-mifflin/scranton.git\n"
    );

    expect(print1).not.toHaveBeenCalled();
    expect(print2).not.toHaveBeenCalled();
  });
});

describe("git credential erase", () => {
  it("makes the next get refresh", async () => {
    await seed({ sessions: { a: session("a") }, fallback: { [SERVER]: "a" } });
    fetchMock.mockImplementation(async () => tokenReply("a", 1));

    await gitCredential(
      "erase",
      `${request("dunder-mifflin/scranton.git").trimEnd()}\ncredential=${accessTokenFor("a")}\n`
    );
    await gitCredential("get", request("dunder-mifflin/scranton.git"));

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(replyOf().credential).toBe(accessTokenFor("a", 1));
  });

  it("keeps the token when git erases an older one", async () => {
    await seed({ sessions: { a: session("a") }, fallback: { [SERVER]: "a" } });

    await gitCredential(
      "erase",
      `${request("dunder-mifflin/scranton.git").trimEnd()}\ncredential=old-token\n`
    );
    await gitCredential("get", request("dunder-mifflin/scranton.git"));

    expect(fetchMock).not.toHaveBeenCalled();
    expect(replyOf().credential).toBe(accessTokenFor("a"));
  });
});
