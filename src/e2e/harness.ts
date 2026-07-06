/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import * as dotenv from "dotenv";
import { spawn } from "node:child_process";
import * as path from "node:path";

// `yarn e2e` always runs from the repository root (vitest sets cwd to the
// config's root), so the CLI under test is the repo's own `p0` launcher,
// which runs the output of `yarn build`.
export const REPO_ROOT = process.cwd();
export const P0_LAUNCHER = path.join(REPO_ROOT, "p0");

// Node IDs and org overrides can live in a git-ignored .env file.
dotenv.config({ path: path.join(REPO_ROOT, ".env") });

/** The P0 organization the suite logs in to before running any test. */
export const E2E_ORG = process.env.P0_E2E_ORG ?? "p0-e2e";

/** Access requests generally require a reason in the e2e org. */
export const E2E_REASON =
  process.env.P0_E2E_REASON ?? "P0 CLI automated e2e test";

export type SshTarget = {
  /** Value passed to `--provider` on the CLI. */
  provider: "aws" | "azure" | "gcloud";
  /** Value of the `provider` field in `p0 ls --json` output for this cloud;
   * gcloud is reported there as "gcp". */
  lsProvider: string;
  node: string | undefined;
};

/** An SSH-able node for one cloud provider in the e2e org. The flow built on
 * top of this target is skipped (with a warning) when its node is not
 * configured, so each provider's spec file can run independently. */
const sshTarget = (
  provider: SshTarget["provider"],
  lsProvider: string,
  node: string | undefined
): SshTarget => {
  if (!node) {
    process.stderr.write(
      `[e2e] P0_E2E_${provider.toUpperCase()}_NODE is not set; skipping the ${provider} ssh flow\n`
    );
  }
  return { provider, lsProvider, node };
};

export const AWS_TARGET = sshTarget("aws", "aws", process.env.P0_E2E_AWS_NODE);
export const AZURE_TARGET = sshTarget(
  "azure",
  "azure",
  process.env.P0_E2E_AZURE_NODE
);
export const GCLOUD_TARGET = sshTarget(
  "gcloud",
  "gcp",
  process.env.P0_E2E_GCLOUD_NODE
);

export type CliResult = {
  code: number | null;
  stdout: string;
  stderr: string;
  /** stdout and stderr interleaved in arrival order, for assertion messages */
  output: string;
};

export type RunOptions = {
  /** Kill the process (SIGTERM, then SIGKILL) after this long */
  timeoutMs?: number;
  /** Extra environment variables for the child */
  env?: NodeJS.ProcessEnv;
  /** Attach the child directly to the terminal instead of capturing output;
   * used for steps that may need user interaction (e.g. a login flow) */
  interactive?: boolean;
};

/** Quotes args containing whitespace so the logged command line is safe to
 * copy-paste into a real shell; the child process itself is spawned without a
 * shell, so this is purely for the log. */
const shellQuote = (arg: string) => (/\s/.test(arg) ? `"${arg}"` : arg);

const childEnv = (extra?: NodeJS.ProcessEnv): NodeJS.ProcessEnv => {
  // P0_SSH_SUDO would silently turn every ssh test into a sudo request, so the
  // suite always controls sudo explicitly.
  const { P0_SSH_SUDO: _ignored, ...env } = process.env;
  return { ...env, ...extra };
};

export const runCommand = (
  command: string,
  args: string[],
  options: RunOptions = {}
): Promise<CliResult> => {
  const { timeoutMs = 15 * 60 * 1000, env, interactive } = options;

  process.stderr.write(
    `\n[e2e] $ ${command} ${args.map(shellQuote).join(" ")}\n`
  );

  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: REPO_ROOT,
      env: childEnv(env),
      stdio: interactive ? "inherit" : ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let output = "";
    let timedOut = false;

    child.stdout?.on("data", (chunk: Buffer) => {
      const text = chunk.toString("utf8");
      stdout += text;
      output += text;
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      const text = chunk.toString("utf8");
      stderr += text;
      output += text;
    });

    const killTimer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 10_000).unref();
    }, timeoutMs);

    child.on("error", (error) => {
      clearTimeout(killTimer);
      reject(new Error(`Failed to run ${command}: ${error.message}`));
    });

    child.on("close", (code) => {
      clearTimeout(killTimer);
      resolve({
        code,
        stdout,
        stderr,
        output: timedOut
          ? `${output}\n[e2e] command timed out after ${timeoutMs} ms`
          : output,
      });
    });
  });
};

/** Runs the built CLI: `p0 <args>` */
export const runP0 = (args: string[], options: RunOptions = {}) =>
  runCommand("node", ["--no-deprecation", P0_LAUNCHER, ...args], options);

/** A unique, greppable token to prove a remote command actually ran. */
export const uniqueMarker = (label: string) =>
  `p0-e2e-${label}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
