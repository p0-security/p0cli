/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../../drivers/stdio";
import { redactPresignedUrls, sshProxy } from "../index";
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

/** A fake child that writes `stderr` to its stderr stream and then exits with
 * `code`, mimicking a process that fails after emitting diagnostic output. */
const makeFailingChild = (stderr: string, code: number) => {
  const child = new EventEmitter() as any;
  child.stderr = new EventEmitter();
  child.kill = vi.fn();
  child.unref = vi.fn();
  setImmediate(() => {
    child.stderr.emit("data", Buffer.from(stderr));
    child.emit("exit", code);
  });
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

describe("GCP connection failure diagnostics", () => {
  // spawnSshNode resolves the provider (and thus its connectionErrorMessage and
  // unprovisionedAccessPatterns) from the SSH_PROVIDERS registry keyed by
  // request.type, so a `gcloud` request exercises the real GCP classifier. The
  // passed sshProvider only supplies the hooks sshProxy itself calls; stub the
  // gcloud login so the test never shells out.
  const gcpProviderWith = (propagationTimeoutMs: number) =>
    ({
      cloudProviderLogin: vi.fn(async () => undefined),
      proxyCommand: () => [
        "gcloud",
        "compute",
        "start-iap-tunnel",
        "my-instance",
        "22",
      ],
      propagationTimeoutMs,
    }) as any;

  const runGcpProxy = (sshProvider: any) =>
    sshProxy({
      authn: {} as any,
      request: {
        type: "gcloud",
        id: "my-instance",
        projectId: "my-project",
        zone: "us-central1-a",
        linuxUserName: "user",
      } as any,
      requestId: "req-1",
      cmdArgs: {} as any,
      privateKey: "pk",
      sshProvider,
      debug: false,
      port: "22",
    });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("surfaces the OS Login hint when SSH auth is rejected (publickey)", async () => {
    mockSpawn.mockImplementation(() =>
      makeFailingChild(
        "my-user@my-instance: Permission denied (publickey).\n",
        255
      )
    );

    // A negative propagation timeout puts endTime in the past, so the first
    // publickey rejection is terminal (no propagation wait) and the classifier
    // replaces the generic "did not propagate" message.
    const error = await runGcpProxy(gcpProviderWith(-1)).catch((e) => e);

    expect(error).toContain("Connected to my-instance");
    expect(error).toContain("most common cause is OS Login");
    expect(error).toContain("enable-oslogin=TRUE");
  });

  it("passes an IAP / tunnel-establishment failure through unchanged", async () => {
    mockSpawn.mockImplementation(() =>
      makeFailingChild(
        "ERROR: (gcloud.compute.start-iap-tunnel) Error while connecting [4003: 'failed to connect to backend'].\n",
        1
      )
    );

    const exitCode = await runGcpProxy(gcpProviderWith(1000));

    // Tunnel failures are intentionally not classified: the original exit code is
    // returned and no OS Login hint is emitted.
    expect(exitCode).toBe(1);
    const printed = (print2 as Mock).mock.calls.map((call) => String(call[0]));
    expect(printed.some((line) => line.includes("OS Login"))).toBe(false);
  });
});

describe("redactPresignedUrls", () => {
  const presigned =
    "https://bucket.s3.amazonaws.com/path/to/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA%2F20260701&X-Amz-Signature=deadbeefcafe&X-Amz-Security-Token=abc123";

  it("strips the query string of a presigned URL, keeping host and key visible", () => {
    expect(
      redactPresignedUrls(["-sSfL", presigned, "-o", "/home/u/file"])
    ).toEqual([
      "-sSfL",
      "https://bucket.s3.amazonaws.com/path/to/key?<redacted-presigned-query>",
      "-o",
      "/home/u/file",
    ]);
  });

  it("redacts even when the arg is wrapped in the shell-escaping quotes createCommand adds", () => {
    const [redacted] = redactPresignedUrls([`"${presigned}"`]);
    expect(redacted).not.toContain("deadbeefcafe");
    expect(redacted).not.toContain("X-Amz-Security-Token");
  });

  it("leaves non-presigned args untouched", () => {
    const args = [
      "ssh",
      "-p",
      "22",
      "user@host",
      "https://example.com/plain?a=b",
    ];
    expect(redactPresignedUrls(args)).toEqual(args);
  });
});
