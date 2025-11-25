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

const getQueueIndicatorPath = (port: number, pid?: number): string => {
  // Use system temp directory for queue indicator files
  // Include PID in filename to allow multiple queue indicators
  const tmpDir = os.tmpdir();
  const pidSuffix = pid ? `-${pid}` : "";
  return join(tmpDir, `p0-login-queue-${port}${pidSuffix}.indicator`);
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
  const queuePath = getQueueIndicatorPath(port, process.pid);
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
  const queuePath = getQueueIndicatorPath(port, process.pid);
  await unlink(queuePath).catch(() => {
    // Ignore errors if file doesn't exist
  });
};

/** Check if someone is waiting in queue */
const hasQueue = async (port: number): Promise<boolean> => {
  const tmpDir = os.tmpdir();
  const queueFilePattern = `p0-login-queue-${port}-`;
  
  try {
    const files = await import("node:fs/promises").then(fs => fs.readdir(tmpDir));
    const queueFiles = files.filter(f => f.startsWith(queueFilePattern) && f.endsWith(".indicator"));
    
    for (const file of queueFiles) {
      try {
        const filePath = join(tmpDir, file);
        const content = await readFile(filePath, "utf-8");
        const indicator = JSON.parse(content) as QueueIndicator;
        // Check if the waiting process is still running
        try {
          process.kill(indicator.waitingPid, 0);
          return true; // At least one process is still waiting
        } catch {
          // Process died, remove stale indicator
          await unlink(filePath).catch(() => {});
        }
      } catch {
        // Error reading file, ignore
      }
    }
    return false;
  } catch {
    return false;
  }
};

/** Get queue position by counting queue indicators with earlier timestamps */
const getQueuePosition = async (port: number, myTimestamp: number): Promise<{ position: number; total: number }> => {
  const tmpDir = os.tmpdir();
  const queueFilePattern = `p0-login-queue-${port}-`;
  
  try {
    const fs = await import("node:fs/promises");
    const files = await fs.readdir(tmpDir);
    const queueFiles = files.filter(f => f.startsWith(queueFilePattern) && f.endsWith(".indicator"));
    
    // Check if lock is held (someone is currently logging in)
    const lockHeld = await isLockHeld(port);
    
    // Collect all active queue members with their timestamps and PIDs
    const activeQueueMembers: Array<{ pid: number; timestamp: number }> = [];
    
    // Count all active queue members
    for (const file of queueFiles) {
      try {
        const filePath = join(tmpDir, file);
        const content = await readFile(filePath, "utf-8");
        const indicator = JSON.parse(content) as QueueIndicator;
        
        // Check if this indicator is from a running process
        try {
          process.kill(indicator.waitingPid, 0);
          // This is an active queue member
          activeQueueMembers.push({
            pid: indicator.waitingPid,
            timestamp: indicator.timestamp,
          });
        } catch {
          // Process died, remove stale indicator
          await unlink(filePath).catch(() => {});
        }
      } catch {
        // Error reading file, ignore
      }
    }
    
    // Sort queue members by timestamp, then by PID (for deterministic ordering with ties)
    activeQueueMembers.sort((a, b) => {
      if (a.timestamp !== b.timestamp) {
        return a.timestamp - b.timestamp;
      }
      // Tie-breaker: use PID for deterministic ordering
      return a.pid - b.pid;
    });
    
    // Find our position in the sorted queue
    // If we're not in the list yet (just created indicator), add ourselves
    let myIndex = activeQueueMembers.findIndex(m => m.pid === process.pid);
    if (myIndex < 0) {
      // Our indicator might not be in the list yet, add it
      activeQueueMembers.push({ pid: process.pid, timestamp: myTimestamp });
      // Re-sort with our entry
      activeQueueMembers.sort((a, b) => {
        if (a.timestamp !== b.timestamp) {
          return a.timestamp - b.timestamp;
        }
        return a.pid - b.pid;
      });
      myIndex = activeQueueMembers.findIndex(m => m.pid === process.pid);
    }
    
    // Calculate position: if lock is held, add 1 for the current login
    // Position 1 = next in line (after current login if lock is held)
    const position = lockHeld 
      ? myIndex + 2 // +1 for 0-based index, +1 for current login
      : myIndex + 1; // +1 for 0-based index
    
    // Total includes: current login (if lock held) + all queue members
    const total = lockHeld ? activeQueueMembers.length + 1 : activeQueueMembers.length;
    
    return { position, total };
  } catch (error) {
    // Fallback: assume we're waiting behind current login
    return { position: 2, total: 2 };
  }
};

/** Check if port is available by trying to create a test server */
const isPortAvailable = async (port: number): Promise<boolean> => {
  return new Promise((resolve) => {
    const testServer = http.createServer();
    testServer.listen(port, () => {
      testServer.close(() => {
        resolve(true);
      });
    });
    testServer.on("error", () => {
      resolve(false);
    });
  });
};

/** Wait for lock to be released with timeout and user prompt */
const waitForLockRelease = async (
  port: number,
  timeoutMs: number = 5 * 60 * 1000 // 5 minutes default
): Promise<boolean> => {
  const POLL_INTERVAL_MS = 2000; // Check every 2 seconds
  const QUEUE_CHECK_INTERVAL_MS = 2000; // Check queue position every 2 seconds
  const startTime = Date.now();
  let elapsedSeconds = 0;
  let lastPosition = 0;
  let lastTotal = 0;
  let lockAcquired = false;
  let lastQueueCheck = 0;

  // Create queue indicator to signal we're waiting
  const myTimestamp = Date.now();
  
  // Print message immediately - this should appear right away
  print2("");
  print2("Another user is currently logging in. Joining queue...");
  
  // Force flush stderr to ensure message appears
  process.stderr.write("", () => {});
  
  await createQueueIndicator(port);

  // Cleanup queue indicator on exit
  const cleanupQueueIndicator = async () => {
    await removeQueueIndicator(port);
  };
  process.once("SIGINT", cleanupQueueIndicator);
  process.once("SIGTERM", cleanupQueueIndicator);

  try {
    // Get initial queue position
    print2("Checking queue position...");
    const initialPosition = await getQueuePosition(port, myTimestamp);
    lastPosition = initialPosition.position;
    lastTotal = initialPosition.total;
    print2(`You are ${lastPosition}/${lastTotal} in the login queue.`);
    print2("");
    
    // Force flush to ensure messages appear
    process.stderr.write("", () => {});

    let lastQueueCheck = 0;
    let lastLockHeld: boolean | undefined = undefined;
    const QUEUE_CHECK_INTERVAL = 2000; // Check queue position every 2 seconds
    
    while (Date.now() - startTime < timeoutMs) {
      // Check if lock is still held
      const lockStillHeld = await isLockHeld(port);
      
      if (!lockStillHeld && !lockAcquired) {
        // Lock is released or stale - check queue position before trying to acquire
        // This ensures we show the correct position (should be 1/1 or 1/X) before acquiring
        const queueInfoBeforeAcquire = await getQueuePosition(port, myTimestamp);
        if (queueInfoBeforeAcquire.position !== lastPosition || queueInfoBeforeAcquire.total !== lastTotal) {
          lastPosition = queueInfoBeforeAcquire.position;
          lastTotal = queueInfoBeforeAcquire.total;
          if (lastPosition === 1 && lastTotal === 1) {
            print2("You are now next in line (1/1). Acquiring lock...");
          } else if (lastPosition === 1) {
            print2(`You are now next in line (1/${lastTotal}). Acquiring lock...`);
          } else {
            print2(`Queue update: You are now ${lastPosition}/${lastTotal} in the login queue.`);
          }
          process.stderr.write("", () => {});
        }
        
        // Try to acquire lock
        if (await acquireLoginLock(port)) {
          // Successfully acquired lock
          lockAcquired = true;
          
          // Check queue position BEFORE removing our indicator, so we can see the total count
          const queueInfoAfterLock = await getQueuePosition(port, myTimestamp);
          
          // Now remove our queue indicator
          await removeQueueIndicator(port);
          
          // Calculate the correct total: if there are other queue members, total = 1 (us) + others
          // If no other queue members, total = 1 (just us)
          const hasOtherQueueMembers = await hasQueue(port);
          const totalCount = hasOtherQueueMembers ? queueInfoAfterLock.total : 1;
          
          if (totalCount === 1) {
            // We're the only one left - we're next in line
            print2("You are now next in line (1/1). Waiting for previous server to close...");
          } else {
            // There are still others waiting, but we're next
            print2(`You are now next in line (1/${totalCount}). Waiting for previous server to close...`);
          }
          process.stderr.write("", () => {});
        } else {
          // Lock was acquired by someone else between check and acquire
          // This means someone else got ahead of us - immediately update queue position
          const queueInfo = await getQueuePosition(port, myTimestamp);
          if (queueInfo.position !== lastPosition || queueInfo.total !== lastTotal) {
            lastPosition = queueInfo.position;
            lastTotal = queueInfo.total;
            if (lastPosition === 1) {
              print2(`You are next in line (1/${lastTotal} in queue). Waiting for current login to complete...`);
            } else if (lastTotal > 5) {
              print2(`Queue update: You are ${lastPosition}/${lastTotal} in the login queue.`);
            } else {
              print2(`Queue update: You are now ${lastPosition}/${lastTotal} in the login queue.`);
            }
            process.stderr.write("", () => {});
          }
          lastQueueCheck = Date.now();
        }
      }
      
      // If we've acquired the lock, check if port is available
      if (lockAcquired) {
        const portAvailable = await isPortAvailable(port);
        if (portAvailable) {
          // Port is available, we can proceed
          process.removeListener("SIGINT", cleanupQueueIndicator);
          process.removeListener("SIGTERM", cleanupQueueIndicator);
          print2("Port is available. Starting login...");
          return true;
        } else {
          // Port still in use, show waiting message
          const elapsed = Math.floor((Date.now() - startTime) / 1000);
          if (elapsed % 5 === 0 && elapsed !== elapsedSeconds) {
            print2(`Waiting for port to become available... (${elapsed} seconds)`);
            elapsedSeconds = elapsed;
            process.stderr.write("", () => {});
          }
        }
      } else {
        // Still waiting for lock - check queue position regularly
        // Also check when lock status changes (someone completes login)
        const now = Date.now();
        const shouldCheckQueue = (now - lastQueueCheck >= QUEUE_CHECK_INTERVAL_MS) || 
                                 (lockStillHeld !== (lastLockHeld ?? true));
        
        if (shouldCheckQueue) {
          const queueInfo = await getQueuePosition(port, myTimestamp);
          if (queueInfo.position !== lastPosition || queueInfo.total !== lastTotal) {
            lastPosition = queueInfo.position;
            lastTotal = queueInfo.total;
            if (lastPosition === 1) {
              print2(`You are next in line (1/${lastTotal} in queue). Waiting for current login to complete...`);
            } else if (lastTotal > 5) {
              // With many users, show more frequent updates
              print2(`Queue update: You are ${lastPosition}/${lastTotal} in the login queue.`);
            } else {
              print2(`Queue update: You are now ${lastPosition}/${lastTotal} in the login queue.`);
            }
            // Force flush after position update
            process.stderr.write("", () => {});
          }
          lastQueueCheck = now;
          lastLockHeld = lockStillHeld;
        }

        // Show progress every 10 seconds (changed from 30 for better visibility)
        const newElapsedSeconds = Math.floor((Date.now() - startTime) / 1000);
        if (newElapsedSeconds !== elapsedSeconds && newElapsedSeconds % 10 === 0 && newElapsedSeconds > 0) {
          print2(`Still waiting... (${newElapsedSeconds} seconds elapsed, position ${lastPosition}/${lastTotal})`);
          elapsedSeconds = newElapsedSeconds;
          // Force flush after progress update
          process.stderr.write("", () => {});
        }
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
          // waitForLockRelease will show queue messages and wait until port is available
          const acquired = await waitForLockRelease(port);
          if (!acquired) {
            throw new Error("Login cancelled while waiting in queue.");
          }
          // waitForLockRelease now waits until port is available, so we can proceed
          lockAcquired = true;
          this.lockPorts.add(port);
        } else {
          // We acquired the lock immediately (no one was waiting)
          lockAcquired = true;
          this.lockPorts.add(port);
        }
      }

      // Create server - on Windows, waitForLockRelease already ensured port is available
      // But we still need to handle the case where port might be taken by non-p0 process
      try {
        server = await this.tryCreateServer(newApp, port);
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
            
            if (response && response.ok) {
              const data = await response.json().catch(() => null);
              if (data?.type === "p0-auth-server" && os === "win") {
                // It's our auth server - another process is already using the port
                // We should release our lock (if we have one) and enter the queue
                // The first process should have the lock, not us
                if (lockAcquired) {
                  // We incorrectly acquired the lock - release it and enter queue
                  await releaseLoginLock(port).catch(() => {});
                  this.lockPorts.delete(port);
                  lockAcquired = false;
                }
                
                // Enter queue to wait for the other login to complete
                print2("Detected another login in progress. Joining queue...");
                print2("");
                const acquired = await waitForLockRelease(port);
                if (!acquired) {
                  throw new Error("Login cancelled while waiting in queue.");
                }
                lockAcquired = true;
                this.lockPorts.add(port);
                // Now try to create server again - waitForLockRelease ensured port is available
                server = await this.tryCreateServer(newApp, port);
                // Server created successfully, break out of error handling
                // We'll continue to the code after the try-catch
              } else {
                // Not our server or not Windows
                if (lockAcquired) {
                  await releaseLoginLock(port).catch(() => {});
                  this.lockPorts.delete(port);
                }
                throw new Error(
                  `Port ${port} is already in use by another process. ` +
                  `Please wait for the other login to complete or close the other process.`
                );
              }
            } else {
              // Not our server or couldn't determine
              if (lockAcquired) {
                await releaseLoginLock(port).catch(() => {});
                this.lockPorts.delete(port);
              }
              throw new Error(
                `Port ${port} is already in use by another process. ` +
                `Please wait for the other login to complete or close the other process.`
              );
            }
          } catch (checkError: any) {
            // If we successfully created the server in the queue path, don't throw
            if (server) {
              // Continue execution
            } else {
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
      
      // If we successfully created the server and we're on Windows, ensure we have the lock
      if (os === "win" && server && !lockAcquired) {
        // We created the server without a lock (first process)
        // Create the lock now so other processes know we're logging in
        await acquireLoginLock(port);
        lockAcquired = true;
        this.lockPorts.add(port);
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
    
    // Set up 5-minute timeout if someone is waiting in queue
    const QUEUE_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
    let queueCheckIntervalId: NodeJS.Timeout | null = null;

    const checkQueueTimeout = async () => {
      if (!(await hasQueue(port))) {
        // No one is waiting, no timeout needed
        return;
      }

      // Check all queue indicators to find the oldest one
      const tmpDir = os.tmpdir();
      const queueFilePattern = `p0-login-queue-${port}-`;
      
      try {
        const files = await import("node:fs/promises").then(fs => fs.readdir(tmpDir));
        const queueFiles = files.filter(f => f.startsWith(queueFilePattern) && f.endsWith(".indicator"));
        
        let oldestTimestamp = Date.now();
        let hasActiveQueue = false;
        
        for (const file of queueFiles) {
          try {
            const filePath = join(tmpDir, file);
            const content = await readFile(filePath, "utf-8");
            const indicator = JSON.parse(content) as QueueIndicator;
            
            // Check if the waiting process is still running
            try {
              process.kill(indicator.waitingPid, 0);
              hasActiveQueue = true;
              if (indicator.timestamp < oldestTimestamp) {
                oldestTimestamp = indicator.timestamp;
              }
            } catch {
              // Process died, remove stale indicator
              await unlink(filePath).catch(() => {});
            }
          } catch {
            // Error reading file, ignore
          }
        }
        
        if (!hasActiveQueue) {
          return; // No active queue members
        }

        // Calculate elapsed time since oldest queue indicator was created
        const elapsed = Date.now() - oldestTimestamp;
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
