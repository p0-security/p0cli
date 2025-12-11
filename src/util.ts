/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { defaultConfig } from "./drivers/env";
import {
  spawn,
  type ChildProcess,
  type ChildProcessByStdio,
  type ChildProcessWithoutNullStreams,
  type SpawnOptions,
  type SpawnOptionsWithoutStdio,
  type SpawnOptionsWithStdioTuple,
  type StdioNull,
  type StdioPipe,
} from "node:child_process";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import type { Readable } from "node:stream";
import open from "open";
import { sys } from "typescript";
import { observedExit } from "./opentelemetry/otel-helpers";

/**
 * Creates a clean environment for child processes by removing FIPS OpenSSL configuration
 * variables that could interfere with external tools not designed for our custom setup.
 */
export const createCleanChildEnv = (
  baseEnv = process.env
): NodeJS.ProcessEnv => {
  const cleanEnv = { ...baseEnv };
  delete cleanEnv.OPENSSL_CONF;
  delete cleanEnv.OPENSSL_MODULES;
  return cleanEnv;
};

/**
 * Wrapped spawn function that automatically provides clean environment for child processes,
 * preventing FIPS OpenSSL configuration from interfering with external tools.
 */
export function spawnWithCleanEnv(
  command: string,
  args?: ReadonlyArray<string>,
  options?: SpawnOptionsWithoutStdio
): ChildProcessWithoutNullStreams;
export function spawnWithCleanEnv(
  command: string,
  args: ReadonlyArray<string>,
  options: SpawnOptionsWithStdioTuple<StdioNull, StdioNull, StdioPipe>
): ChildProcessByStdio<null, null, Readable>;
export function spawnWithCleanEnv(
  command: string,
  args: ReadonlyArray<string>,
  options: SpawnOptionsWithStdioTuple<StdioNull, StdioPipe, StdioPipe>
): ChildProcessByStdio<null, Readable, Readable>;
export function spawnWithCleanEnv(
  command: string,
  args: ReadonlyArray<string>,
  options: SpawnOptions
): ChildProcess;
export function spawnWithCleanEnv(
  command: string,
  args?: ReadonlyArray<string>,
  options?: SpawnOptions
): ChildProcess {
  return spawn(command, args || [], {
    ...options,
    env: options?.env || createCleanChildEnv(),
  });
}

export const getAppPath = () =>
  process.env.P0_APP_PATH ?? process.argv[1] ?? "p0";

export const getAppName = () => path.basename(getAppPath());

export const P0_PATH = path.join(
  os.homedir(),
  defaultConfig.environment === "production"
    ? ".p0"
    : `.p0-${defaultConfig.environment}`
);

/** Waits the specified delay (in ms)
 *
 * The returned promise is cancelable:
 * ```
 * const wait = sleep(10);
 * ...
 * wait.cancel();
 * ```
 */
export const sleep = (timeoutMillis: number) => {
  let timer: NodeJS.Timeout | undefined = undefined;
  const promise = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, timeoutMillis);
  });
  return Object.assign(promise, { cancel: () => clearTimeout(timer) });
};

/** Wrap a promise in a timeout
 *
 * If the promise does not resolve within the interval, throws an
 * error.
 */
export const timeout = async <T extends NonNullable<any>>(
  promise: Promise<NonNullable<T>>,
  timeoutMillis: number
) => {
  const wait = sleep(timeoutMillis);
  const result = await Promise.race([wait, promise]);
  if (result === undefined) throw new Error("Timeout");
  wait.cancel();
  return result;
};

/** Executes a subprocess, waiting for exit, and collecting all output
 *
 * Throws an error if the exit code is non-zero
 */
export const exec = async (
  command: string,
  args: string[],
  options?: SpawnOptionsWithoutStdio & {
    /** If true, throws an error if exit code is non-zero */
    check?: boolean;
  }
) =>
  new Promise<{ code: number | null; stdout: string; stderr: string }>(
    (resolve, reject) => {
      try {
        const out: (Buffer | string)[] = [];
        const err: (Buffer | string)[] = [];
        const child = spawnWithCleanEnv(command, args, {
          ...(options ?? {}),
          stdio: "pipe",
        });
        child.stdout.on("data", (d) => out.push(d));
        child.stderr.on("data", (d) => err.push(d));

        // The close event is emitted after the child process has exited (the 'exit' event) and all of its
        // stdio (standard input, standard output, and standard error) streams have been closed.
        // See https://nodejs.org/api/child_process.html#event-close
        child.on("close", (code) => {
          const stdout = out.map((d) => d.toString()).join("");
          const stderr = err.map((d) => d.toString()).join("");
          const result = { code, stdout, stderr };
          if (code !== 0 && options?.check)
            reject(
              Object.assign(new Error("Sub-process exited with code"), result)
            );
          resolve(result);
        });

        // without a handler for the "error" event, an uncaught exception will be thrown that will crash
        // the process entirely. This can happen if the process fails to spawn, for example, due to the
        // command not being found
        child.on("error", (error) => {
          reject(error);
        });
      } catch (error) {
        reject(error);
      }
    }
  );

export const throwAssertNever = (value: never) => {
  throw assertNever(value);
};

// If the condition is true, aborts the process before throwing the error
export const conditionalAbortBeforeThrow =
  (abortBeforeThrow: boolean) => (err: any) => {
    if (abortBeforeThrow) {
      observedExit(1, err);
    }
    throw err;
  };

export const assertNever = (value: never) => {
  return unexpectedValueError(value);
};

export const unexpectedValueError = (value: any) =>
  new Error(`Unexpected code state: value ${value} had unexpected type`);

/**
 * Performs a case-insensitive comparison of two strings. This uses
 * `localeCompare()`, which is safer than `toLowerCase()` or `toUpperCase()` for
 * non-ASCII characters and is the generally-accepted best practice. See:
 * https://stackoverflow.com/a/2140723
 *
 * @param a The first string to compare
 * @param b The second string to compare
 * @returns true if the strings are equal, ignoring case
 */
export const ciEquals = (a: string, b: string) =>
  a.localeCompare(b, undefined, { sensitivity: "accent" }) === 0;

export const delay = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

type OperatingSystem = "linux" | "mac" | "unknown" | "win";
export const getOperatingSystem = (): OperatingSystem => {
  const platform = process.platform;
  if (platform === "win32") {
    return "win";
  } else if (platform === "darwin") {
    return "mac";
  } else if (platform === "linux") {
    return "linux";
  } else {
    return "unknown";
  }
};

/**
 * Wraps a command with the operating-system specific method
 * executing it.
 * @param command the command to wrap
 * @param args the arguments to be passed to the command
 * @returns the command and arguments to be passed to spawn
 */
export const osSafeCommand = (command: string, args: string[]) => {
  const isWindows = getOperatingSystem() === "win";

  // On Windows, when installing the Azure CLI, the main az file is
  // a .cmd (shell script) file rather than a .exe (binary executable) file,
  // so when calling spawn, it cannot be located except via cmd.exe
  // Unlike in MacOS, the underlying Windows OS API that spawn uses doesn't
  // resolve .CMD files by default
  return isWindows
    ? { command: "cmd.exe", args: ["/d", "/s", "/c", command, ...args] }
    : { command, args };
};

const OPEN_TIMEOUT_MS = 5000;

/**
 * Wraps the 'open' function to provide a timeout and error handling. This is
 * necessary because on some OSes, 'open' may fail depending on whether the machine
 * has the required dependencies installed (e.g., 'xdg-open' on Linux). Without
 * proper error handling, the promise may hang indefinitely or throw an unhandled exception,
 * which would crash the application entirely.
 * @param target the URL to open
 * @param options options to be passed directly to the 'open' function
 */
export const osSafeOpen = async (
  target: string,
  options?: open.Options
): Promise<void> => {
  const child = await open(target, options);

  return new Promise((resolve, reject) => {
    let settled = false;

    const settle = () => {
      settled = true;
      child.removeListener("error", errorHandler);
      child.removeListener("spawn", spawnHandler);
    };

    // Timeout to avoid hanging indefinitely
    const timeout = setTimeout(() => {
      if (!settled) {
        settle();
        reject(new Error("Failed to open target: timeout exceeded"));
      }
    }, OPEN_TIMEOUT_MS);

    const errorHandler = (err: Error) => {
      if (!settled) {
        settle();
        clearTimeout(timeout);
        reject(err);
      }
    };

    const spawnHandler = () => {
      if (!settled) {
        settle();
        clearTimeout(timeout);
        resolve();
      }
    };

    // Attach handlers synchronously to catch immediate errors
    child.on("error", errorHandler);
    child.on("spawn", spawnHandler);

    // Handle already-spawned case (process started before handlers attached)
    if (child.pid !== undefined) {
      spawnHandler();
    }
  });
};
