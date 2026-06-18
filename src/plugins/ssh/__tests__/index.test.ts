/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { sshProxy } from "../index";
import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, Mock, vi } from "vitest";

vi.mock("node:child_process", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:child_process")>()),
  spawn: vi.fn(),
}));

vi.mock("../../../drivers/api", () => ({
  auditSshSessionActivity: vi.fn(async () => undefined),
  fetchSshHostKeys: vi.fn(),
}));

vi.mock("../../../drivers/stdio", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../drivers/stdio")>()),
  print2: vi.fn(),
}));

const mockSpawn = spawn as unknown as Mock;

/** A minimal stand-in for a spawned ChildProcess that exits cleanly once
 * spawnSshNode has attached its listeners. */
const makeFakeChild = () => {
  const child = new EventEmitter() as any;
  child.stderr = new EventEmitter();
  child.kill = vi.fn();
  child.unref = vi.fn();
  setImmediate(() => child.emit("exit", 0));
  return child;
};

const CREDENTIAL = {
  AWS_ACCESS_KEY_ID: "AKIATEST",
  AWS_SECRET_ACCESS_KEY: "secret-access-key",
  AWS_SESSION_TOKEN: "session-token-123",
  AWS_SECURITY_TOKEN: "session-token-123",
};

const fakeAwsProvider = {
  cloudProviderLogin: vi.fn(async () => CREDENTIAL),
  proxyCommand: () => ["aws", "ssm", "start-session", "--target", "i-abc123"],
  propagationTimeoutMs: 1000,
} as any;

const runSshProxy = () =>
  sshProxy({
    authn: {} as any,
    request: { type: "aws" } as any,
    requestId: "req-1",
    cmdArgs: {} as any,
    privateKey: "pk",
    sshProvider: fakeAwsProvider,
    debug: false,
    port: "22",
  });

const awsEnv = (env: NodeJS.ProcessEnv) => ({
  AWS_ACCESS_KEY_ID: env.AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY: env.AWS_SECRET_ACCESS_KEY,
  AWS_SESSION_TOKEN: env.AWS_SESSION_TOKEN,
  AWS_SECURITY_TOKEN: env.AWS_SECURITY_TOKEN,
});

describe("sshProxy credential handoff stays shell-agnostic", () => {
  const originalShell = process.env.SHELL;

  beforeEach(() => {
    vi.clearAllMocks();
    mockSpawn.mockImplementation(() => makeFakeChild());
  });

  afterEach(() => {
    process.env.SHELL = originalShell;
  });

  it("injects AWS credentials into the spawned child env, without a shell", async () => {
    process.env.SHELL = "/usr/bin/fish";
    await runSshProxy();

    expect(mockSpawn).toHaveBeenCalledTimes(1);
    const [command, , options] = mockSpawn.mock.calls[0]!;

    // The spawned process is the binary itself, never the user's login shell,
    // and Node is told not to interpose a shell.
    expect(command).toBe("aws");
    expect(options.shell).toBe(false);

    // Credentials are delivered as environment variables on the child process.
    expect(options.env.AWS_SESSION_TOKEN).toBe("session-token-123");
    expect(options.env.AWS_ACCESS_KEY_ID).toBe("AKIATEST");
    expect(options.env.AWS_SECRET_ACCESS_KEY).toBe("secret-access-key");
  });

  it("spawns identically regardless of $SHELL (login shell is never consulted)", async () => {
    process.env.SHELL = "/usr/bin/fish";
    await runSshProxy();
    const [fishCmd, fishArgs, fishOpts] = mockSpawn.mock.calls[0]!;

    vi.clearAllMocks();
    mockSpawn.mockImplementation(() => makeFakeChild());

    process.env.SHELL = "/bin/bash";
    await runSshProxy();
    const [bashCmd, bashArgs, bashOpts] = mockSpawn.mock.calls[0]!;

    // Same command, args, and shell:false no matter the login shell.
    expect(fishCmd).toBe("aws");
    expect(bashCmd).toBe("aws");
    expect(fishArgs).toEqual(bashArgs);
    expect(fishOpts.shell).toBe(false);
    expect(bashOpts.shell).toBe(false);

    // Same injected credentials either way.
    expect(awsEnv(fishOpts.env)).toEqual(awsEnv(bashOpts.env));
    expect(fishOpts.env.AWS_SESSION_TOKEN).toBe("session-token-123");

    // $SHELL is merely passed through (env is cloned), not used to decide
    // anything — proving the credential handoff does not depend on it.
    expect(fishOpts.env.SHELL).toBe("/usr/bin/fish");
    expect(bashOpts.env.SHELL).toBe("/bin/bash");
  });
});
