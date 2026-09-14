/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { spawnClaude } from "../mcp";
import { describe, expect, it } from "vitest";

// Stands in for the `claude` executable: these exercise the real child
// process wiring, which is the thing that was broken. Run node rather than a
// shell, so the tests work on Windows too.
const node = (script: string, env: NodeJS.ProcessEnv = process.env) =>
  spawnClaude(process.execPath, ["-e", script], env);

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
