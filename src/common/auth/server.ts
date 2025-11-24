/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

/** Implements a local auth server, which can receive auth tokens from an OIDC app */
import { sleep } from "../../util";
import express from "express";
import { noop } from "lodash";
import { readFile } from "node:fs/promises";
import http from "node:http";
import { join, resolve } from "node:path";
import { isSea, getAssetAsBlob } from "node:sea";
import { Readable } from "node:stream";
import { randomUUID } from "node:crypto";

const ASSETS_PATH = resolve(`${join(__dirname, "..", "..")}/public`);
const LANDING_HTML_PATH = "redirect-landing.html";
const FAVICON_PATH = "favicon.ico";

/** A small amount of time is necessary prior to shutting down the redirect server to
 * properly render the redirect-landing page
 */
const SERVER_SHUTDOWN_WAIT_MILLIS = 2e3;

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

// Shared server manager to handle multiple concurrent logins on the same port
type SessionHandler<T, U> = {
  completeAuth: (value: any, token: T, redirectUrl: string) => Promise<U>;
  value: any;
  redirectUrl: string; // Store the base redirect URL (without session parameter)
  sessionId: string; // Store the session ID for reference
  redirectResolve: (result: U) => void;
  redirectReject: (error: any) => void;
  cleanup: () => void;
};

class SharedServerManager {
  private servers = new Map<number, http.Server>();
  private apps = new Map<number, express.Application>();
  private sessions = new Map<string, SessionHandler<any, any>>();
  private pageBytes: Buffer | null = null;
  private faviconBytes: Buffer | null = null;

  private async getStaticAssets() {
    if (!this.pageBytes || !this.faviconBytes) {
      this.pageBytes = await loadStaticAsset(LANDING_HTML_PATH);
      this.faviconBytes = await loadStaticAsset(FAVICON_PATH);
    }
    return { pageBytes: this.pageBytes, faviconBytes: this.faviconBytes };
  }

  async getOrCreateServer(port: number): Promise<{ server: http.Server; app: express.Application }> {
    let server = this.servers.get(port);
    let app = this.apps.get(port);

    if (!server || !app) {
      app = express();
      
      // Set up favicon handler
      app.get("/favicon.ico", async (_, res) => {
        const { faviconBytes } = await this.getStaticAssets();
        pipeToResponse(faviconBytes, res, "image/x-icon");
      });

      // Set up session-based callback handler
      app.get("/", async (req, res) => {
        // Extract session ID from state parameter
        // State format: "session:<sessionId>" or "azure_login:session:<sessionId>"
        const state = req.query.state as string;
        if (!state) {
          res.status(400).send("Missing state parameter");
          return;
        }

        let sessionId: string | undefined;
        if (state.startsWith("session:")) {
          sessionId = state.substring(8); // Remove "session:" prefix
        } else if (state.startsWith("azure_login:session:")) {
          sessionId = state.substring(20); // Remove "azure_login:session:" prefix
        } else {
          // Fallback: try to find session ID in state (for backwards compatibility)
          const parts = state.split(":session:");
          if (parts.length === 2) {
            sessionId = parts[1];
          }
        }

        if (!sessionId) {
          res.status(400).send("Invalid state parameter format");
          return;
        }

        const handler = this.sessions.get(sessionId);
        if (!handler) {
          res.status(404).send("Session not found or expired");
          return;
        }

        const token = req.query;
        const { pageBytes } = await this.getStaticAssets();
        
        try {
          // Use the base redirect URL (without session) for token exchange
          // OAuth spec requires redirect_uri in token exchange to match authorization request
          const result = await handler.completeAuth(
            handler.value,
            token as any,
            handler.redirectUrl
          );
          pipeToResponse(pageBytes, res, "text/html; charset=utf-8");
          handler.redirectResolve(result);
        } catch (error: any) {
          res.status(500).send(error?.message ?? error);
          handler.redirectReject(error);
        }
      });

      // Create server and handle port conflicts
      server = await new Promise<http.Server>((resolve, reject) => {
        const newServer = app.listen(port);
        
        newServer.once("listening", () => {
          resolve(newServer);
        });
        
        newServer.once("error", (error: NodeJS.ErrnoException) => {
          if (error.code === "EADDRINUSE") {
            // Port is in use - this means another process has the port
            // We can't share across processes, so we need to fail
            reject(new Error(
              `Port ${port} is already in use by another process. ` +
              `Please wait for the other login to complete or close the other process.`
            ));
          } else {
            reject(error);
          }
        });
      });

      this.servers.set(port, server);
      this.apps.set(port, app);
    }

    return { server, app };
  }

  registerSession<T, U>(
    sessionId: string,
    handler: SessionHandler<T, U>
  ) {
    this.sessions.set(sessionId, handler);
  }

  unregisterSession(sessionId: string) {
    this.sessions.delete(sessionId);
  }

  async closeServer(port: number) {
    const server = this.servers.get(port);
    if (server) {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }).catch(noop);
      this.servers.delete(port);
      this.apps.delete(port);
    }
  }
}

const sharedServerManager = new SharedServerManager();

/** Waits for an OIDC authorization redirect using a locally mounted server */
export const withRedirectServer = async <S, T, U>(
  beginAuth: (server: http.Server, redirectUrl: string, sessionId: string) => Promise<S>,
  completeAuth: (value: S, token: T, redirectUrl: string) => Promise<U>,
  options?: { port?: number }
) => {
  if (options?.port === undefined) {
    throw new Error("Port is required for OAuth redirect server");
  }

  const port = options.port;
  const sessionId = randomUUID();

  let redirectResolve: (result: U) => void;
  let redirectReject: (error: any) => void;
  let value: S;
  const redirectPromise = new Promise<U>((resolve, reject) => {
    redirectResolve = resolve;
    redirectReject = reject;
  });

  // Get or create shared server for this port
  const { server } = await sharedServerManager.getOrCreateServer(port);
  // Use base redirect URL (without session parameter) - session ID will be encoded in state parameter
  const redirectUrl = `http://127.0.0.1:${port}`;

  // Register session handler
  const handler: SessionHandler<T, U> = {
    completeAuth: completeAuth as any,
    value: undefined as any,
    redirectUrl: redirectUrl, // Store the base redirect URL
    sessionId: sessionId, // Store session ID for reference
    redirectResolve,
    redirectReject,
    cleanup: () => {
      sharedServerManager.unregisterSession(sessionId);
    },
  };
  sharedServerManager.registerSession(sessionId, handler);

  // Set up cleanup handler for process interruption
  const cleanup = async () => {
    handler.cleanup();
    // Don't close the server here - other sessions might be using it
    // The server will be closed when the process exits
  };

  // Register signal handlers to ensure cleanup on interruption
  const signalHandler = () => {
    void cleanup().finally(() => process.exit(0));
  };
  process.once("SIGINT", signalHandler);
  process.once("SIGTERM", signalHandler);

  try {
    value = await beginAuth(server, redirectUrl, sessionId);
    handler.value = value;
    return await redirectPromise;
  } finally {
    process.removeListener("SIGINT", signalHandler);
    process.removeListener("SIGTERM", signalHandler);

    await cleanup();
  }
};
