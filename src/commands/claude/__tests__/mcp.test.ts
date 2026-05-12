/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Authn } from "../../../types/identity";
import { EventEmitter } from "node:events";
import { promisify } from "node:util";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import yargs from "yargs";

const mocks = vi.hoisted(() => ({
  authFetch: vi.fn(),
  authenticate: vi.fn(),
  debug: vi.fn(),
  mkdir: vi.fn(),
  print2: vi.fn(),
  readFile: vi.fn(),
  spawn: vi.fn(),
  writeFile: vi.fn(),
}));

vi.mock("../../../drivers/api", () => ({
  authFetch: mocks.authFetch,
  tenantUrl: (tenant: string) => `https://app.example.com/o/${tenant}`,
}));

vi.mock("../../../drivers/auth", () => ({
  authenticate: mocks.authenticate,
}));

vi.mock("../../../drivers/stdio", () => ({
  debug: mocks.debug,
  print2: mocks.print2,
}));

vi.mock("node:fs/promises", () => ({
  default: {
    mkdir: mocks.mkdir,
    readFile: mocks.readFile,
    writeFile: mocks.writeFile,
  },
}));

vi.mock("node:child_process", () => {
  const exec = vi.fn() as Mock & {
    [promisify.custom]: (command: string) => Promise<{
      stdout: string;
      stderr: string;
    }>;
  };
  exec[promisify.custom] = vi.fn(async (command: string) => ({
    stdout: command === "claude --version" ? "1.2.3\n" : "/usr/bin/claude\n",
    stderr: "",
  }));
  return { exec };
});

vi.mock("cross-spawn", () => ({
  default: mocks.spawn,
}));

const makeAuthn = (orgSlug: string) =>
  ({
    identity: {
      credential: {},
      org: { slug: orgSlug },
    },
    getToken: vi.fn(async () => "token"),
  }) as unknown as Authn;

const mockMcpApi = () => {
  mocks.authFetch.mockImplementation(
    async (_authn: Authn, args: { method: string; url: string }) => {
      if (args.method === "POST" && args.url.endsWith("/mcp/clients")) {
        return {
          client: {
            id: "new-client",
            redirectUri: "http://localhost:8080",
            secret: "new-secret",
          },
        };
      }
      if (args.method === "GET" && args.url.endsWith("/mcp/servers/p0")) {
        return {
          server: {
            id: "p0",
            url: "https://mcp.example.com/p0",
          },
        };
      }
      throw new Error(`Unexpected request: ${args.method} ${args.url}`);
    }
  );
};

const mockSpawnSuccess = () => {
  mocks.spawn.mockImplementation(() => {
    const proc = new EventEmitter();
    process.nextTick(() => proc.emit("exit", 0));
    return proc;
  });
};

describe("claude mcp", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.P0_ORG;
    mocks.mkdir.mockResolvedValue(undefined);
    mocks.writeFile.mockResolvedValue(undefined);
    mockMcpApi();
    mockSpawnSuccess();
  });

  it("requires a subcommand", async () => {
    const { mcpCommand } = await import("../mcp.js");

    await expect(
      Promise.resolve().then(() =>
        mcpCommand(yargs()).exitProcess(false).parseAsync("")
      )
    ).rejects.toThrow("Not enough non-option arguments");
  });

  it("ignores cached MCP clients registered for a different org", async () => {
    const authn = makeAuthn("new-org");
    mocks.authenticate.mockResolvedValue(authn);
    mocks.readFile.mockResolvedValue(
      JSON.stringify({
        orgSlug: "old-org",
        client: {
          id: "old-client",
          redirectUri: "http://localhost:8080",
          secret: "old-secret",
        },
      })
    );

    const { mcpCommand } = await import("../mcp.js");
    await mcpCommand(yargs()).exitProcess(false).parseAsync("add p0");

    expect(mocks.authFetch).toHaveBeenCalledWith(
      authn,
      expect.objectContaining({
        method: "POST",
        url: "https://app.example.com/o/new-org/mcp/clients",
      })
    );
    expect(JSON.parse(mocks.writeFile.mock.calls[0]![1])).toEqual({
      orgSlug: "new-org",
      client: {
        id: "new-client",
        redirectUri: "http://localhost:8080",
        secret: "new-secret",
      },
    });
    expect(mocks.spawn.mock.calls[0]![2]).toEqual(
      expect.objectContaining({
        env: expect.objectContaining({ MCP_CLIENT_SECRET: "new-secret" }),
      })
    );
  });

  it("reuses cached MCP clients registered for the authenticated org", async () => {
    const authn = makeAuthn("new-org");
    mocks.authenticate.mockResolvedValue(authn);
    mocks.readFile.mockResolvedValue(
      JSON.stringify({
        orgSlug: "new-org",
        client: {
          id: "cached-client",
          redirectUri: "http://localhost:8080",
          secret: "cached-secret",
        },
      })
    );

    const { mcpCommand } = await import("../mcp.js");
    await mcpCommand(yargs()).exitProcess(false).parseAsync("add p0");

    expect(mocks.authFetch).not.toHaveBeenCalledWith(
      authn,
      expect.objectContaining({ method: "POST" })
    );
    expect(mocks.writeFile).not.toHaveBeenCalled();
    expect(mocks.spawn.mock.calls[0]![2]).toEqual(
      expect.objectContaining({
        env: expect.objectContaining({ MCP_CLIENT_SECRET: "cached-secret" }),
      })
    );
  });
});
