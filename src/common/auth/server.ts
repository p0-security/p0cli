/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

/** Implements a local auth server, which can receive auth tokens from an OIDC app */
import { sleep } from "../../util";
import express from "express";
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
  start: (server: http.Server) => Promise<S>,
  complete: (value: S, token: T) => Promise<U>,
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

  // load static assets
  const pageBytes = await loadStaticAsset(LANDING_HTML_PATH);
  const faviconBytes = await loadStaticAsset(FAVICON_PATH);

  // handle favicon
  app.get("/favicon.ico", (_, res) => {
    pipeToResponse(faviconBytes, res, "image/x-icon");
  });

  // handle redirect
  const redirectRouter = express.Router();
  redirectRouter.get("/", (req, res) => {
    const token = req.query as T;
    complete(value, token)
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

  try {
    value = await start(server);
    return await redirectPromise;
  } finally {
    await sleep(SERVER_SHUTDOWN_WAIT_MILLIS);
    server.closeAllConnections();
    server.unref();
  }
};
