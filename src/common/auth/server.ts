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

/** Waits for an OIDC authorization redirect using a locally mounted server */
export const withRedirectServer = async <S, T, U>(
  beginAuth: (server: http.Server) => Promise<S>,
  completeAuth: (value: S, token: T) => Promise<U>,
  options?: { port?: number }
) => {
  const app = express();

  let redirectResolve: (result: U) => void;
  let redirectReject: (error: any) => void;
  let value: S;
  const redirectPromise = new Promise<U>((resolve, reject) => {
    redirectResolve = resolve;
    redirectReject = reject;
  });

  const pageBytes = await loadStaticAsset(LANDING_HTML_PATH);
  const faviconBytes = await loadStaticAsset(FAVICON_PATH);

  app.get("/favicon.ico", (_, res) => {
    pipeToResponse(faviconBytes, res, "image/x-icon");
  });

  const redirectRouter = express.Router();
  redirectRouter.get("/", (req, res) => {
    const token = req.query as T;
    completeAuth(value, token)
      .then((result) => {
        pipeToResponse(pageBytes, res, "text/html; charset=utf-8");
        redirectResolve(result);
      })
      .catch((error: any) => {
        res.status(500).send(error?.message ?? error);
        redirectReject(error);
      });
  });

  app.use(redirectRouter);

  const server = app.listen(options?.port ?? 0);

  // Set up cleanup handler for process interruption
  const cleanup = async () => {
    await sleep(SERVER_SHUTDOWN_WAIT_MILLIS);
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    }).catch(noop);
  };

  // Register signal handlers to ensure cleanup on interruption
  const signalHandler = () => {
    void cleanup().finally(() => process.exit(0));
  };
  process.once("SIGINT", signalHandler);
  process.once("SIGTERM", signalHandler);

  // Wait for server to start listening or fail
  await new Promise<void>((resolve, reject) => {
    server.once("listening", () => resolve());
    server.once("error", (error) => {
      redirectReject(error);
      reject(error);
    });
  });

  try {
    value = await beginAuth(server);
    return await redirectPromise;
  } finally {
    process.removeListener("SIGINT", signalHandler);
    process.removeListener("SIGTERM", signalHandler);

    await cleanup();
  }
};
