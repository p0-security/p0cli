/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { gitLogin } from "../login";
import { claimKey, readStore } from "../store";
import {
  ISSUER,
  SERVER,
  TOKEN_ENDPOINT,
  accessTokenFor,
  jsonResponse,
  makeTempDir,
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

const metadata = (url: string) => {
  if (url === `${SERVER}/.well-known/oauth-protected-resource`) {
    return jsonResponse({
      authorization_servers: [ISSUER],
    });
  }
  if (url === `${ISSUER}/.well-known/oauth-authorization-server`) {
    return jsonResponse({ issuer: ISSUER, token_endpoint: TOKEN_ENDPOINT });
  }
  return undefined;
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

describe("git login", () => {
  it("stores the Session, claims its repositories and makes it the fallback", async () => {
    fetchMock.mockImplementation(
      async (url) =>
        metadata(String(url)) ?? tokenReply("a", 0, ["Dunder-Mifflin/Scranton"])
    );

    await gitLogin({ serverUrl: `${SERVER}/`, code: "abc" });

    const [, init] = fetchMock.mock.calls[2] ?? [];
    expect(Object.fromEntries(new URLSearchParams(String(init?.body)))).toEqual(
      {
        grant_type: "urn:p0:params:oauth:grant-type:setup-code",
        code: "abc",
        client_id: "p0-git",
      }
    );
    const store = await readStore();
    expect(store.sessions.a).toMatchObject({
      serverUrl: SERVER,
      tokenEndpoint: TOKEN_ENDPOINT,
      accessToken: accessTokenFor("a"),
      refreshToken: "refresh-a-0",
    });
    expect(store.claims).toEqual({
      [claimKey(SERVER, "dunder-mifflin/scranton")]: "a",
    });
    expect(store.fallback).toEqual({ [SERVER]: "a" });
  });

  it("keeps the other Session's claims", async () => {
    fetchMock.mockImplementation(
      async (url) =>
        metadata(String(url)) ?? tokenReply("a", 0, ["Dunder-Mifflin/Scranton"])
    );
    await gitLogin({ serverUrl: SERVER, code: "abc" });
    fetchMock.mockImplementation(
      async (url) =>
        metadata(String(url)) ?? tokenReply("b", 0, ["Dunder-Mifflin/Stamford"])
    );

    await gitLogin({ serverUrl: SERVER, code: "def" });

    const store = await readStore();
    expect(store.claims).toEqual({
      [claimKey(SERVER, "dunder-mifflin/scranton")]: "a",
      [claimKey(SERVER, "dunder-mifflin/stamford")]: "b",
    });
    expect(store.fallback).toEqual({ [SERVER]: "b" });
  });

  it("refuses a used or expired code", async () => {
    fetchMock.mockImplementation(
      async (url) =>
        metadata(String(url)) ?? jsonResponse({ error: "invalid_grant" }, 400)
    );

    await expect(gitLogin({ serverUrl: SERVER, code: "abc" })).rejects.toMatch(
      "The code is not valid"
    );
    expect((await readStore()).sessions).toEqual({});
  });

  it("refuses a token endpoint on another origin", async () => {
    fetchMock.mockImplementation(async (url) =>
      String(url).endsWith("oauth-authorization-server")
        ? jsonResponse({
            issuer: ISSUER,
            token_endpoint: "https://evil.example.com/token",
          })
        : (metadata(String(url)) ?? tokenReply("a", 0))
    );

    await expect(gitLogin({ serverUrl: SERVER, code: "abc" })).rejects.toMatch(
      "another origin"
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("refuses a plain HTTP server that is not on this machine", async () => {
    await expect(
      gitLogin({
        serverUrl: "http://gateway.example.com/mcps/github",
        code: "abc",
      })
    ).rejects.toMatch("must use HTTPS");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not follow redirects", async () => {
    fetchMock.mockImplementation(
      async (url) => metadata(String(url)) ?? tokenReply("a", 0)
    );

    await gitLogin({ serverUrl: SERVER, code: "abc" });

    expect(
      fetchMock.mock.calls.every(([, init]) => init?.redirect === "error")
    ).toBe(true);
  });
});
