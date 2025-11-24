/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

/** Implements a local auth server, which can receive auth tokens from an OIDC app */
import express from "express";
import { noop } from "lodash";
import { readFile, writeFile, unlink, access } from "node:fs/promises";
import { constants } from "node:fs";
import http from "node:http";
import { join, resolve } from "node:path";
import { isSea, getAssetAsBlob } from "node:sea";
import { Readable } from "node:stream";
import os from "node:os";
import { getOperatingSystem } from "../../util";
import { print2 } from "../../drivers/stdio";
import { sleep } from "../../util";

const ASSETS_PATH = resolve(`${join(__dirname, "..", "..")}/public`);
const LANDING_HTML_PATH = "redirect-landing.html";
const FAVICON_PATH = "favicon.ico";

/** A small amount of time is necessary prior to shutting down the redirect server to
 * properly render the redirect-landing page
 */
const SERVER_SHUTDOWN_WAIT_MILLIS = 2e3;

/** Lock file management for queue system on Windows/RDS */
interface LockData {
  pid: number;
  timestamp: number;
  port: number;
}

interface QueueIndicator {
  waitingPid: number;
  timestamp: number;
  port: number;
}

const getLockFilePath = (port: number): string => {
  // Use system temp directory for lock files
  const tmpDir = os.tmpdir();
  return join(tmpDir, `p0-login-${port}.lock`);
};

const getQueueIndicatorPath = (port: number): string => {
  // Use system temp directory for queue indicator files
  const tmpDir = os.tmpdir();
  return join(tmpDir, `p0-login-queue-${port}.indicator`);
};

const readLockFile = async (lockPath: string): Promise<LockData | null> => {
  try {
    const content = await readFile(lockPath, "utf-8");
    return JSON.parse(content) as LockData;
  } catch {
    return null;
  }
};

const fileExists = async (path: string): Promise<boolean> => {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
};

/** Check if lock is currently held by a running process */
const isLockHeld = async (port: number): Promise<boolean> => {
  const lockPath = getLockFilePath(port);
  
  if (!(await fileExists(lockPath))) {
    return false;
  }

  const lockData = await readLockFile(lockPath);
  if (!lockData) {
    return false;
  }

  // Validate that the process is still running using process.kill(pid, 0)
  // This doesn't actually kill the process, just checks if it exists
  try {
    process.kill(lockData.pid, 0);
    return true; // Process is running, lock is valid
  } catch {
    // Process doesn't exist (died/crashed/cancelled)
    // Lock is stale, remove it
    await unlink(lockPath).catch(() => {});
    return false;
  }
};

/** Try to acquire lock, returns true if successful */
const acquireLoginLock = async (port: number): Promise<boolean> => {
  const lockPath = getLockFilePath(port);

  // Check if lock exists and is valid
  if (await isLockHeld(port)) {
    return false; // Lock is held by another process
  }

  // Lock doesn't exist or is stale, try to create it
  const lockData: LockData = {
    pid: process.pid,
    timestamp: Date.now(),
    port: port,
  };

  try {
    // Use 'wx' flag to create file exclusively (fails if file exists)
    await writeFile(lockPath, JSON.stringify(lockData), { flag: "wx" });
    return true;
  } catch {
    // File was created by another process between our check and write
    // Check again if it's held
    return !(await isLockHeld(port));
  }
};

/** Release lock when login completes */
const releaseLoginLock = async (port: number): Promise<void> => {
  const lockPath = getLockFilePath(port);
  await unlink(lockPath).catch(() => {
    // Ignore errors if file doesn't exist
  });
};

/** Create queue indicator to signal that someone is waiting */
const createQueueIndicator = async (port: number): Promise<void> => {
  const queuePath = getQueueIndicatorPath(port);
  const indicator: QueueIndicator = {
    waitingPid: process.pid,
    timestamp: Date.now(),
    port: port,
  };
  await writeFile(queuePath, JSON.stringify(indicator)).catch(() => {
    // Ignore errors
  });
};

/** Remove queue indicator */
const removeQueueIndicator = async (port: number): Promise<void> => {
  const queuePath = getQueueIndicatorPath(port);
  await unlink(queuePath).catch(() => {
    // Ignore errors if file doesn't exist
  });
};

/** Check if someone is waiting in queue */
const hasQueue = async (port: number): Promise<boolean> => {
  const queuePath = getQueueIndicatorPath(port);
  if (!(await fileExists(queuePath))) {
    return false;
  }

  try {
    const content = await readFile(queuePath, "utf-8");
    const indicator = JSON.parse(content) as QueueIndicator;
    // Check if the waiting process is still running
    try {
      process.kill(indicator.waitingPid, 0);
      return true; // Process is still waiting
    } catch {
      // Process died, remove stale indicator
      await unlink(queuePath).catch(() => {});
      return false;
    }
  } catch {
    return false;
  }
};

/** Wait for lock to be released with timeout and user prompt */
const waitForLockRelease = async (
  port: number,
  timeoutMs: number = 5 * 60 * 1000 // 5 minutes default
): Promise<boolean> => {
  const POLL_INTERVAL_MS = 2000; // Check every 2 seconds
  const startTime = Date.now();
  let elapsedSeconds = 0;

  // Create queue indicator to signal we're waiting
  await createQueueIndicator(port);

  // Cleanup queue indicator on exit
  const cleanupQueueIndicator = async () => {
    await removeQueueIndicator(port);
  };
  process.once("SIGINT", cleanupQueueIndicator);
  process.once("SIGTERM", cleanupQueueIndicator);

  try {
    print2("Another user is currently logging in. Waiting in queue...");

    while (Date.now() - startTime < timeoutMs) {
      if (!(await isLockHeld(port))) {
        // Lock is released or stale, try to acquire
        if (await acquireLoginLock(port)) {
          // Successfully acquired lock, remove queue indicator
          await removeQueueIndicator(port);
          process.removeListener("SIGINT", cleanupQueueIndicator);
          process.removeListener("SIGTERM", cleanupQueueIndicator);
          return true;
        }
      }

      // Show progress every 10 seconds
      const newElapsedSeconds = Math.floor((Date.now() - startTime) / 1000);
      if (newElapsedSeconds !== elapsedSeconds && newElapsedSeconds % 10 === 0) {
        print2(`Waiting... (${newElapsedSeconds} seconds)`);
        elapsedSeconds = newElapsedSeconds;
      }

      await sleep(POLL_INTERVAL_MS);
    }

    // Timeout reached, prompt user
    const inquirer = (await import("inquirer")).default;
    const { continueWaiting } = await inquirer.prompt([
      {
        type: "confirm",
        name: "continueWaiting",
        message:
          "Login is taking longer than expected. Continue waiting? (y/n)",
        default: true,
      },
    ]);

    if (continueWaiting) {
      // Reset timeout and continue waiting
      return waitForLockRelease(port, timeoutMs);
    } else {
      await removeQueueIndicator(port);
      process.removeListener("SIGINT", cleanupQueueIndicator);
      process.removeListener("SIGTERM", cleanupQueueIndicator);
      print2(
        "Login cancelled. Please try again later or check if another login process is stuck."
      );
      return false;
    }
  } catch (error) {
    await removeQueueIndicator(port);
    process.removeListener("SIGINT", cleanupQueueIndicator);
    process.removeListener("SIGTERM", cleanupQueueIndicator);
    throw error;
  }
};

const pipeToResponse = (
  bytes: Buffer,
  res: express.Response,
  contentType: string
) => {
  const stream = Readable.from(bytes);
  res.status(200);
  res.setHeader("Content-Type", contentType);
  res.setHeader("Content-Length", bytes.length);
  stream.pipe(res);
};

const loadStaticAsset = async (path: string): Promise<Buffer> => {
  if (isSea()) {
    const blob = getAssetAsBlob(path);
    return Buffer.from(await blob.arrayBuffer());
  }
  const filePath = join(ASSETS_PATH, path);
  const bytes = await readFile(filePath);
  return bytes;
};

// Shared server manager to handle OAuth redirects
type AuthHandler<T, U> = {
  completeAuth: (value: any, token: T, redirectUrl: string) => Promise<U>;
  value: any;
  redirectUrl: string;
  redirectResolve: (result: U) => void;
  redirectReject: (error: any) => void;
  cleanup: () => void;
};

class SharedServerManager {
  private servers = new Map<number, http.Server>();
  private apps = new Map<number, express.Application>();
  private activeHandlers = new Map<number, AuthHandler<any, any>>(); // One active handler per port
  private pageBytes: Buffer | null = null;
  private faviconBytes: Buffer | null = null;
  private lockPorts = new Set<number>(); // Track ports that have locks

  private async getStaticAssets() {
    if (!this.pageBytes || !this.faviconBytes) {
      this.pageBytes = await loadStaticAsset(LANDING_HTML_PATH);
      this.faviconBytes = await loadStaticAsset(FAVICON_PATH);
    }
    return { pageBytes: this.pageBytes, faviconBytes: this.faviconBytes };
  }

  private async tryCreateServer(
    app: express.Application,
    port: number
  ): Promise<http.Server> {
    return new Promise<http.Server>((resolve, reject) => {
      const newServer = app.listen(port);

      newServer.once("listening", () => {
        resolve(newServer);
      });

      newServer.once("error", (error: NodeJS.ErrnoException) => {
        if (error.code === "EADDRINUSE") {
          reject(error);
        } else {
          reject(error);
        }
      });
    });
  }

  async getOrCreateServer(port: number): Promise<{ server: http.Server; app: express.Application }> {
    let server = this.servers.get(port);
    let app = this.apps.get(port);

    if (!server || !app) {
      const newApp = express();
      
      // Set up favicon handler
      newApp.get("/favicon.ico", async (_, res) => {
        const { faviconBytes } = await this.getStaticAssets();
        pipeToResponse(faviconBytes, res, "image/x-icon");
      });

      // Set up health endpoint
      newApp.get("/health", (_, res) => {
        res.json({
          type: "p0-auth-server",
          activeSessions: this.activeHandlers.has(port) ? 1 : 0,
          port: port,
        });
      });

      // Set up OAuth callback handler
      newApp.get("/", async (req, res) => {
        try {
          const handler = this.activeHandlers.get(port);
          if (!handler) {
            res.status(404).send("No active login session found");
            return;
          }

          const token = req.query;
          const { pageBytes } = await this.getStaticAssets();
          
          const result = await handler.completeAuth(
            handler.value,
            token as any,
            handler.redirectUrl
          );
          pipeToResponse(pageBytes, res, "text/html; charset=utf-8");
          handler.redirectResolve(result);
        } catch (error: any) {
          res.status(500).send(error?.message ?? error);
          const handler = this.activeHandlers.get(port);
          if (handler) {
            handler.redirectReject(error);
          }
        }
      });

      // On Windows/RDS, check for lock and wait in queue before creating server
      const os = getOperatingSystem();
      let lockAcquired = false;
      if (os === "win") {
        // Try to acquire lock first
        if (!(await acquireLoginLock(port))) {
          // Lock is held, wait in queue
          const acquired = await waitForLockRelease(port);
          if (!acquired) {
            throw new Error("Login cancelled while waiting in queue.");
          }
          // After acquiring lock from queue, wait a bit for previous server to close
          // The previous process releases the lock in clearActiveHandler, which has a 2s delay
          // before closing the server, so we wait a bit more to ensure it's closed
          await sleep(3000);
        }
        // Lock acquired, proceed with server creation
        lockAcquired = true;
        this.lockPorts.add(port);
      }

      // Create server and handle port conflicts
      // On Windows, if we acquired the lock, the previous server should be closing
      // We may need to retry a few times as the server closes
      let serverCreated = false;
      let retryCount = 0;
      const MAX_RETRIES = 10; // Try up to 10 times (20 seconds total)
      
      while (!serverCreated && retryCount < MAX_RETRIES) {
        try {
          const newServer = await this.tryCreateServer(newApp, port);
          server = newServer;
          serverCreated = true;
        } catch (error: any) {
          if (error.code === "EADDRINUSE") {
            // Port is in use - check if it's our auth server
            try {
              const healthUrl = `http://127.0.0.1:${port}/health`;
              const controller = new AbortController();
              const timeoutId = setTimeout(() => controller.abort(), 1000);
              
              const response = await fetch(healthUrl, {
                method: "GET",
                signal: controller.signal,
              }).catch(() => null);
              
              clearTimeout(timeoutId);
              
              // If it's our auth server and we're on Windows with lock acquired, wait and retry
              if (response && response.ok) {
                const data = await response.json().catch(() => null);
                if (data?.type === "p0-auth-server" && os === "win" && lockAcquired) {
                  // Server is still closing, wait a bit and retry
                  retryCount++;
                  if (retryCount < MAX_RETRIES) {
                    await sleep(2000);
                    continue; // Retry
                  } else {
                    // Max retries reached, release lock and error
                    if (lockAcquired) {
                      await releaseLoginLock(port).catch(() => {});
                      this.lockPorts.delete(port);
                    }
                    throw new Error(
                      `Port ${port} is still in use after waiting. The previous login session may be stuck. ` +
                      `Please close any other p0 login processes and try again.`
                    );
                  }
                } else {
                  // Not our server or not Windows - release lock if we had one
                  if (lockAcquired) {
                    await releaseLoginLock(port).catch(() => {});
                    this.lockPorts.delete(port);
                  }
                  throw new Error(
                    `Port ${port} is already in use by another p0 login session. ` +
                    `Please wait for the other login to complete, or if you're the only user, ` +
                    `close any other p0 login processes and try again.`
                  );
                }
              } else {
                // Not our server or couldn't determine - release lock if we had one
                if (lockAcquired) {
                  await releaseLoginLock(port).catch(() => {});
                  this.lockPorts.delete(port);
                }
                throw new Error(
                  `Port ${port} is already in use. ` +
                  `Please wait for the other login to complete or close the other process.`
                );
              }
            } catch (checkError: any) {
              // Release lock on any error
              if (lockAcquired) {
                await releaseLoginLock(port).catch(() => {});
                this.lockPorts.delete(port);
              }
              // If it's our error from above, rethrow it
              if (checkError.message && checkError.message.includes("Port")) {
                throw checkError;
              }
              // Otherwise, provide the standard error
              throw new Error(
                `Port ${port} is already in use by another process. ` +
                `Please wait for the other login to complete or close the other process.`
              );
            }
          } else {
            // Non-EADDRINUSE error - release lock if we had one
            if (lockAcquired) {
              await releaseLoginLock(port).catch(() => {});
              this.lockPorts.delete(port);
            }
            throw error;
          }
        }
      }

      if (!server) {
        // This shouldn't happen, but TypeScript needs this check
        throw new Error("Failed to create server after retries");
      }

      app = newApp;
      this.servers.set(port, server);
      this.apps.set(port, app);
    }

    return { server, app };
  }

  setActiveHandler<T, U>(port: number, handler: AuthHandler<T, U>) {
    this.activeHandlers.set(port, handler);
  }

  clearActiveHandler(port: number) {
    this.activeHandlers.delete(port);
    
    // Release lock if we had one
    if (this.lockPorts.has(port)) {
      releaseLoginLock(port).catch(() => {
        // Ignore errors when releasing lock
      });
      this.lockPorts.delete(port);
    }
    
    // Wait a bit before closing to ensure browser callback completes
    setTimeout(() => {
      // Double-check that there's still no active handler (in case a new one started)
      if (!this.activeHandlers.has(port)) {
        this.closeServer(port);
      }
    }, SERVER_SHUTDOWN_WAIT_MILLIS);
  }

  async closeServer(port: number) {
    const server = this.servers.get(port);
    if (server) {
      // Close all connections first
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }).catch(noop);
      this.servers.delete(port);
      this.apps.delete(port);
      this.activeHandlers.delete(port);
      
      // Release lock if we had one
      if (this.lockPorts.has(port)) {
        await releaseLoginLock(port).catch(() => {
          // Ignore errors when releasing lock
        });
        this.lockPorts.delete(port);
      }
    }
  }
}

const sharedServerManager = new SharedServerManager();

/** Waits for an OIDC authorization redirect using a locally mounted server */
export const withRedirectServer = async <S, T, U>(
  beginAuth: (server: http.Server, redirectUrl: string) => Promise<S>,
  completeAuth: (value: S, token: T, redirectUrl: string) => Promise<U>,
  options?: { port?: number }
) => {
  if (options?.port === undefined) {
    throw new Error("Port is required for OAuth redirect server");
  }

  const port = options.port;
  let value: S;
  
  // Create promise and capture resolve/reject functions
  let redirectResolve: ((result: U) => void) | undefined;
  let redirectReject: ((error: any) => void) | undefined;
  
  const redirectPromise = new Promise<U>((resolve, reject) => {
    redirectResolve = resolve;
    redirectReject = reject;
  });

  // TypeScript needs these to be definitely assigned
  if (!redirectResolve || !redirectReject) {
    throw new Error("Failed to initialize promise handlers");
  }

  // Get or create shared server for this port
  const { server } = await sharedServerManager.getOrCreateServer(port);
  const redirectUrl = `http://127.0.0.1:${port}`;

  // Create handler and register it as active
  const handler: AuthHandler<T, U> = {
    completeAuth: completeAuth as any,
    value: undefined as any,
    redirectUrl: redirectUrl,
    redirectResolve: redirectResolve,
    redirectReject: redirectReject,
    cleanup: () => {
      sharedServerManager.clearActiveHandler(port);
    },
  };
  sharedServerManager.setActiveHandler(port, handler);

  // Set up cleanup handler for process interruption
  const cleanup = async () => {
    handler.cleanup();
    // Release lock if we had one
    await releaseLoginLock(port).catch(() => {
      // Ignore errors when releasing lock
    });
  };

  // Register signal handlers to ensure cleanup on interruption
  const signalHandler = () => {
    void cleanup().finally(() => process.exit(0));
  };
  process.once("SIGINT", signalHandler);
  process.once("SIGTERM", signalHandler);

  try {
    // Call beginAuth which opens the browser
    value = await beginAuth(server, redirectUrl);
    // Update handler with the value (pkce) so completeAuth can use it when callback arrives
    handler.value = value;
    
    // Set up 120-second timeout if someone is waiting in queue
    const QUEUE_TIMEOUT_MS = 120 * 1000; // 120 seconds
    let queueCheckIntervalId: NodeJS.Timeout | null = null;

    const checkQueueTimeout = async () => {
      const queuePath = getQueueIndicatorPath(port);
      if (!(await fileExists(queuePath))) {
        // No one is waiting, no timeout needed
        return;
      }

      try {
        const content = await readFile(queuePath, "utf-8");
        const indicator = JSON.parse(content) as QueueIndicator;
        
        // Check if the waiting process is still running
        try {
          process.kill(indicator.waitingPid, 0);
        } catch {
          // Process died, no need to timeout
          return;
        }

        // Calculate elapsed time since queue indicator was created
        const elapsed = Date.now() - indicator.timestamp;
        if (elapsed >= QUEUE_TIMEOUT_MS) {
          // Timeout reached - cancel login
          print2(
            "\nLogin timeout: Your login session has been cancelled because another user is waiting in queue."
          );
          print2(
            "You have been logged out of the login process. Please try again later.\n"
          );
          if (queueCheckIntervalId) {
            clearInterval(queueCheckIntervalId);
          }
          const timeoutError = new Error(
            "Login cancelled due to timeout. Another user is waiting in queue. Your login session has been terminated."
          );
          if (redirectReject) {
            redirectReject(timeoutError);
          }
          await cleanup();
          // The error will be thrown when redirectPromise is awaited
        }
      } catch {
        // Error reading queue indicator, ignore
      }
    };

    // Check for queue every 5 seconds
    queueCheckIntervalId = setInterval(checkQueueTimeout, 5000);
    
    // Wait for the OAuth callback to complete
    try {
      return await redirectPromise;
    } finally {
      // Clean up timeout checkers
      if (queueCheckIntervalId) {
        clearInterval(queueCheckIntervalId);
      }
    }
  } catch (error) {
    // If beginAuth fails, reject the promise
    redirectReject(error);
    throw error;
  } finally {
    process.removeListener("SIGINT", signalHandler);
    process.removeListener("SIGTERM", signalHandler);

    await cleanup();
  }
};
