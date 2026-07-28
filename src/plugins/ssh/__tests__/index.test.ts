/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../../drivers/stdio";
import { sshOrScp, sshProxy } from "../index";
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

    // $SHELL is pinned to /bin/sh in the child env: OpenSSH executes
    // ProxyCommand and Match exec via `$SHELL -c`, and `fish -c` — unlike
    // `sh -c` — sources the user's config.fish, which can override the
    // injected AWS_* credentials before `aws ssm start-session` runs (CX-464).
    expect(fishOpts.env.SHELL).toBe("/bin/sh");
    expect(bashOpts.env.SHELL).toBe("/bin/sh");
  });
});

// A hard rejection of the SSM StartSession call (e.g. the 403 <UnauthorizedRequest>
// body produced by clock skew, a TLS-intercepting proxy, or credentials mangled
// between p0 and the ProxyCommand) can never succeed on retry. It must abort the
// access-propagation wait immediately with a classified message instead of
// blind-retrying for 30s and reporting "Access did not propagate" (CX-464).
describe("terminal StartSession failures abort the propagation retry loop", () => {
  // `sshProxy` spawns the `aws` binary directly (it IS the ProxyCommand,
  // e.g. in the native `ssh-proxy` integration fish users hit) — its stderr
  // never contains an outer ssh's "Connection closed"/kex line, unlike the
  // direct `p0 ssh` flow where ssh itself is the spawned child. Terminal
  // classification must fire from the bare aws error alone.
  const AWS_403_STDERR =
    "aws: [ERROR]: An error occurred (403) when calling the StartSession operation: Server authentication failed: <UnauthorizedRequest><message>Forbidden.</message></UnauthorizedRequest>\n";

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // request.type "aws" makes spawnSshNode resolve the real awsSshProvider
  // internally, so its terminalAccessPatterns/connectionErrorMessage apply;
  // the passed provider controls only the propagation window.
  const runAwsProxy = (propagationTimeoutMs: number) =>
    sshProxy({
      authn: {} as any,
      request: { type: "aws", region: "us-west-2" } as any,
      requestId: "req-1",
      cmdArgs: {} as any,
      privateKey: "pk",
      sshProvider: { ...fakeAwsProvider, propagationTimeoutMs },
      debug: false,
      port: "22",
    });

  it("rejects on the first 403 with the classified error instead of retrying", async () => {
    mockSpawn.mockImplementation(() => makeFailingChild(AWS_403_STDERR, 255));

    // endTime is well in the future: without terminal classification this
    // would retry every 5s until the window closes.
    const error = await runAwsProxy(30_000).catch((e) => e);

    expect(mockSpawn).toHaveBeenCalledTimes(1);
    expect(error).toContain("AWS rejected the SSM StartSession call");
    expect(error).toContain(
      "<UnauthorizedRequest><message>Forbidden.</message></UnauthorizedRequest>"
    );
    expect(error).not.toContain("did not propagate");
  });

  it("still treats a bare connection-closed error as retryable propagation delay", async () => {
    mockSpawn.mockImplementation(() =>
      makeFailingChild(
        "kex_exchange_identification: Connection closed by remote host\n",
        255
      )
    );

    // A past-due endTime makes the retryable failure exhaust the window: it
    // must still report the propagation message, proving the connection-closed
    // line alone is not misclassified as terminal.
    const error = await runAwsProxy(-1).catch((e) => e);

    expect(error).toContain("did not propagate");
  });
});

describe("GCP connection failure diagnostics", () => {
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

// Providers like the Azure jump host build their ProxyCommand as an authenticated `ssh`
// invocation, so it needs the identity file/certificate minted by setup/setupProxy. That data
// is threaded to proxyCommand as an explicit argument (not held as provider state), and these
// tests pin down that both sshOrScp and sshProxy actually pass it through, for both SSH and SCP.
describe("proxyCommand receives setup/setupProxy credentials", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSpawn.mockImplementation(() => makeFakeChild());
  });

  const credentials = {
    identityFile: "/tmp/jump-host-key",
    certificatePath: "/tmp/jump-host-cert",
  };

  const fakeJumpHostLikeProvider = () => ({
    cloudProviderLogin: vi.fn(async () => undefined),
    setup: vi.fn(async () => ({
      sshOptions: [],
      teardown: vi.fn(async () => {}),
      ...credentials,
    })),
    setupProxy: vi.fn(async () => ({
      port: "22",
      teardown: vi.fn(async () => {}),
      ...credentials,
    })),
    proxyCommand: vi.fn(() => ["ssh", "-W", "10.0.0.1:22", "jump-host"]),
    reproCommands: () => undefined,
    preTestAccessPropagationArgs: () => undefined,
    propagationTimeoutMs: 1000,
    unprovisionedAccessPatterns: [],
  });

  const request = {
    type: "azure",
    id: "10.0.0.1",
    linuxUserName: "user",
  } as any;

  it("sshOrScp passes setup()'s credentials to proxyCommand for an SSH session", async () => {
    const sshProvider = fakeJumpHostLikeProvider();

    await sshOrScp({
      authn: {} as any,
      request,
      requestId: "req-1",
      cmdArgs: { destination: "10.0.0.1", arguments: [] } as any,
      privateKey: "pk",
      sshProvider: sshProvider as any,
      sshHostKeys: undefined,
    });

    expect(sshProvider.proxyCommand).toHaveBeenCalledWith(
      request,
      undefined,
      expect.objectContaining(credentials)
    );
  });

  it("sshOrScp passes setup()'s credentials to proxyCommand for an SCP transfer", async () => {
    const sshProvider = fakeJumpHostLikeProvider();

    await sshOrScp({
      authn: {} as any,
      request,
      requestId: "req-1",
      cmdArgs: {
        source: "/local/file",
        destination: "10.0.0.1:/remote/file",
      } as any,
      privateKey: "pk",
      sshProvider: sshProvider as any,
      sshHostKeys: undefined,
    });

    expect(sshProvider.proxyCommand).toHaveBeenCalledWith(
      request,
      undefined,
      expect.objectContaining(credentials)
    );
  });

  it("sshProxy passes setupProxy()'s credentials to proxyCommand", async () => {
    const sshProvider = fakeJumpHostLikeProvider();

    await sshProxy({
      authn: {} as any,
      request,
      requestId: "req-1",
      cmdArgs: {} as any,
      privateKey: "pk",
      sshProvider: sshProvider as any,
      debug: false,
      port: "22",
    });

    expect(sshProvider.proxyCommand).toHaveBeenCalledWith(
      request,
      "22",
      expect.objectContaining(credentials)
    );
  });
});

// A `--sudo` session runs a `sudo -nv` pre-test to wait for the sudoers grant to
// propagate. The Azure providers classify propagation from stderr:
// `Sorry, user ... may not run sudo` means "still propagating" and
// `sudo: a password is required` means "provisioned". A user granted passwordless
// (NOPASSWD) sudo hits neither branch — `sudo -nv` just exits 0 with no output —
// so the pre-test must treat a clean exit as "access propagated" instead of
// looping until the propagation timeout (the "stuck pre-testing" bug).
describe("sudo pre-test access propagation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // Mirrors the Azure providers: sudo commands are pre-tested with `sudo -nv`.
  // A negative propagation timeout puts endTime in the past, so a pre-test that
  // is *not* recognized as propagated fails immediately instead of retrying —
  // letting us assert the exit-0 short-circuit without waiting on a real timer.
  const sudoProvider = (propagationTimeoutMs: number) =>
    ({
      cloudProviderLogin: vi.fn(async () => undefined),
      proxyCommand: vi.fn(() => ["nc", "localhost", "22"]),
      reproCommands: () => undefined,
      preTestAccessPropagationArgs: (cmdArgs: any) => ({
        ...cmdArgs,
        command: "sudo",
        arguments: ["-nv"],
      }),
      propagationTimeoutMs,
    }) as any;

  // type: "azure" (no jump host) makes spawnSshNode resolve the real
  // azureBastionSshProvider internally, whose provisionedAccessPatterns only
  // match `sudo: a password is required` — never emitted for NOPASSWD sudo.
  const request = {
    type: "azure",
    id: "localhost",
    linuxUserName: "user",
  } as any;

  const runSudoSsh = (sshProvider: any) =>
    sshOrScp({
      authn: {} as any,
      request,
      requestId: "req-1",
      cmdArgs: { sudo: true, destination: "my-vm", arguments: [] } as any,
      privateKey: "pk",
      sshProvider,
      sshHostKeys: undefined,
    });

  it("proceeds to the session when a passwordless `sudo -nv` pre-test exits 0", async () => {
    // Every spawned child exits 0 with no stderr, mimicking NOPASSWD sudo where
    // `sudo -nv` succeeds silently. Without treating exit 0 as propagated, the
    // past-due endTime would make this reject as "did not propagate".
    mockSpawn.mockImplementation(() => makeFakeChild());

    await expect(runSudoSsh(sudoProvider(-1))).resolves.toBe(0);

    // Both the pre-test probe and the real session ran.
    expect(mockSpawn).toHaveBeenCalledTimes(2);
    const [preTestCommand, preTestArgs] = mockSpawn.mock.calls[0]!;
    expect(preTestCommand).toBe("ssh");
    expect((preTestArgs as string[]).join(" ")).toContain('sudo "-nv"');
  });

  it("keeps failing when the user is still not a sudoer after the window closes", async () => {
    // While the grant is still propagating, `sudo -nv` prints the not-a-sudoer
    // message and exits non-zero; with endTime in the past this is terminal.
    mockSpawn.mockImplementation(() =>
      makeFailingChild("Sorry, user miguel may not run sudo on my-vm.\n", 1)
    );

    await expect(runSudoSsh(sudoProvider(-1))).rejects.toMatch(
      /did not propagate/
    );

    // Only the pre-test ran; the session is never reached.
    expect(mockSpawn).toHaveBeenCalledTimes(1);
  });
});
