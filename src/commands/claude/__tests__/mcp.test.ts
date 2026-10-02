/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { clientPath, spawnClaude, toCreateClientRequest } from "../mcp";
import { describe, expect, it } from "vitest";

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

// The fields the controller requires of a `client_credential_post`
// registration, and the platforms it accepts. Copied from
// `McpConfidentialClientCreateRequest` in
// `@p0-security/api-specs/specs/controller/tenant/mcp/v1/openapi.yaml`, which
// is the contract the controller validates this request against.
const REQUIRED_FIELDS = [
  "hostname",
  "platform",
  "redirectUri",
  "type",
  "version",
] as const;
const PLATFORMS = ["claude-code", "claude-agents", "custom"];

describe("toCreateClientRequest", () => {
  const request = toCreateClientRequest({
    hostname: "my-laptop",
    version: "1.2.3",
    callbackPort: 8080,
  });

  it("sends every field the controller requires", () => {
    // A missing field fails the whole command with a schema error from the
    // controller, which is what happened when the two last drifted apart.
    expect(Object.keys(request).sort()).toEqual([...REQUIRED_FIELDS].sort());
  });

  it("sends no field the controller does not define", () => {
    for (const field of Object.keys(request)) {
      expect(REQUIRED_FIELDS).toContain(field);
    }
  });

  it("selects the confidential-client variant", () => {
    // `type` is the discriminator. Without it the controller cannot tell which
    // variant of the union to check the rest of the body against.
    expect(request.type).toBe("client_credential_post");
  });

  it("names a platform the controller accepts", () => {
    expect(PLATFORMS).toContain(request.platform);
  });

  it("sends every value as a string", () => {
    for (const value of Object.values(request)) {
      expect(typeof value).toBe("string");
    }
  });

  it("points the redirect at the callback port", () => {
    expect(request.redirectUri).toBe("http://localhost:8080");
  });

  it("falls back to the default callback port", () => {
    const fallback = toCreateClientRequest({
      hostname: "my-laptop",
      version: "1.2.3",
    });
    expect(fallback.redirectUri).toMatch(/^http:\/\/localhost:\d+$/);
  });
});
