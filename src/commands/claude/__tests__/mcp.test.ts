/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { clientPath, provisionServer, spawnClaude } from "../mcp";
import { describe, expect, it, vi } from "vitest";

// Stands in for the `claude` executable: these exercise the real child
// process wiring, which is the thing that was broken. Run node rather than a
// shell, so the tests work on Windows too.
const node = (script: string, env: NodeJS.ProcessEnv = process.env) =>
  spawnClaude(process.execPath, ["-e", script], env);

describe("clientPath", () => {
  it("gives each organization its own cache file", () => {
    // Registrations are tenant-scoped, so reusing one organization's client
    // for another fails at the gateway with "no active registration".
    expect(clientPath("p0-test-agentic")).not.toBe(clientPath("p0-security"));
  });

  it("is stable for the same organization", () => {
    expect(clientPath("p0-security")).toBe(clientPath("p0-security"));
  });

  it("names the file after the organization", () => {
    expect(clientPath("p0-security")).toMatch(
      /[\\/]claude[\\/]mcp-client-p0-security\.json$/
    );
  });

  it("does not let an organization slug escape the p0 directory", () => {
    expect(clientPath("../../evil")).toMatch(
      /[\\/]claude[\\/]mcp-client-evil\.json$/
    );
  });
});

describe("MCP client secret debug output", () => {
  it("reports that the secret is set without logging its value", async () => {
    const secret = "sentinel-oauth-client-secret";
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const runClaude = vi.fn().mockResolvedValue(undefined);

    try {
      await provisionServer(
        {
          debug: true,
          callbackPort: 52566,
          scope: undefined,
          server: "server",
        },
        {
          client: {
            id: "client-id",
            redirectUri: "http://localhost:52566",
            secret,
          },
          server: { id: "client-id", url: "https://example.com" },
        },
        { server: { id: "server-id", url: "https://example.com" } },
        "claude",
        runClaude
      );

      expect(error).toHaveBeenCalledWith("Client secret", "set");
      expect(error.mock.calls.flat().join(" ")).not.toContain(secret);
      expect(runClaude).toHaveBeenCalledWith(
        "claude",
        expect.any(Array),
        expect.objectContaining({ MCP_CLIENT_SECRET: secret })
      );
      expect(runClaude.mock.calls[0]![1]).not.toContain(secret);
    } finally {
      error.mockRestore();
    }
  });
});

describe("spawnClaude", () => {
  it("resolves when claude exits 0", async () => {
    await expect(node("process.exit(0)")).resolves.toBeUndefined();
  });

  it("rejects when claude exits non-zero", async () => {
    await expect(node("process.exit(3)")).rejects.toBe(
      '"claude mcp add" exited with code 3'
    );
  });

  it("rejects when claude is terminated by a signal", async () => {
    await expect(node('process.kill(process.pid, "SIGTERM")')).rejects.toBe(
      '"claude mcp add" was terminated by SIGTERM'
    );
  });

  it("rejects when claude cannot be spawned", async () => {
    await expect(
      spawnClaude("./no-such-claude-executable", [], process.env)
    ).rejects.toMatch(/^Could not run "claude": .*ENOENT/);
  });

  it("passes the client secret via the environment", async () => {
    // The secret is delivered out of band so it never lands on disk; if it
    // stopped reaching the child, auth would fail well after this command.
    await expect(
      node('process.exit(process.env.MCP_CLIENT_SECRET === "s3cret" ? 0 : 1)', {
        ...process.env,
        MCP_CLIENT_SECRET: "s3cret",
      })
    ).resolves.toBeUndefined();
  });
});
