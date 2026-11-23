/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

/** Implements a local auth server, which can receive auth tokens from an OIDC app */
import { getAppName, sleep } from "../../util";
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

/** Waits for an authorization redirect, or a form POST, using a locally
 * mounted server
 *
 * @param options.accepts Answers a token that fails this check with a 400
 *   response, and keeps waiting
 * @param options.host Accepts connections only on this address, such as
 *   `127.0.0.1`. Without it, the server accepts them on every interface.
 * @param options.post Gets the token from a form POST to this path, such as a
 *   SAML response, in place of the query of a GET to `/`
 */
export const withRedirectServer = async <S, T, U>(
  beginAuth: (server: http.Server) => Promise<S>,
  completeAuth: (value: S, token: T) => Promise<U>,
  options?: {
    accepts?: (token: T) => boolean;
    host?: string;
    port?: number;
    post?: string;
  }
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
  const onRedirect = (token: T, res: express.Response) => {
    if (options?.accepts && !options.accepts(token)) {
      res.status(400).send("This response isn't for this sign-in.");
      return;
    }
    completeAuth(value, token)
      .then((result) => {
        pipeToResponse(pageBytes, res, "text/html; charset=utf-8");
        redirectResolve(result);
      })
      .catch((error: any) => {
        res.status(500).send(error?.message ?? error);
        redirectReject(error);
      });
  };
  if (options?.post) {
    redirectRouter.post(
      options.post,
      express.urlencoded({ extended: false, limit: "1mb" }),
      (req, res) => onRedirect(req.body as T, res)
    );
    redirectRouter.use(
      (
        error: any,
        _req: express.Request,
        res: express.Response,
        _next: express.NextFunction
      ) => {
        res.status(400).send(error?.message ?? error);
        redirectReject(error);
      }
    );
  } else {
    redirectRouter.get("/", (req, res) => onRedirect(req.query as T, res));
  }

  app.use(redirectRouter);

  const port = options?.port ?? 0;
  const server = options?.host
    ? app.listen(port, options.host)
    : app.listen(port);

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
    // NOTE: Cannot use exitProcess() here - OAuth server runs outside of traced command context
    void cleanup().finally(() => process.exit(0));
  };
  process.once("SIGINT", signalHandler);
  process.once("SIGTERM", signalHandler);

  // Wait for server to start listening or fail
  // Rejects only this promise: redirectPromise is never awaited when listen fails,
  // so rejecting it would surface as an unhandled rejection
  await new Promise<void>((resolve, reject) => {
    server.once("listening", () => resolve());
    server.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code === "EADDRINUSE") {
        reject(
          `Sign-in failed: port ${port} is already in use, probably by another \`${getAppName()}\` sign-in waiting for the browser.\nFinish or cancel that sign-in (Ctrl+C in its terminal), then run this command again.`
        );
      } else {
        reject(error);
      }
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
