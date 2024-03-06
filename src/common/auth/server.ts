/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

/** Implements a local auth server, which can receive auth tokens from an OIDC app */
import { sleep } from "../../util";
import express from "express";
import http from "node:http";
import { dirname } from "node:path";

const ROOT_PATH = `${dirname(require.main!.filename)}/dist`;

/** A small amount of time is necessary prior to shutting down the redirect server to
 * properly render the redirect-landing page
 */
const SERVER_SHUTDOWN_WAIT_MILLIS = 2e3;

/** Waits for an OIDC authorization redirect using a locally mounted server */
export const withRedirectServer = async <S, T, U>(
  start: (server: http.Server) => Promise<S>,
  complete: (value: S, token: T) => Promise<U>,
  options?: { port?: number }
) => {
  const app = express();
  app.use(express.static(`${ROOT_PATH}/public`));

  let redirectResolve: (result: U) => void;
  let redirectReject: (error: any) => void;
  let value: S;
  const redirectPromise = new Promise<U>((resolve, reject) => {
    redirectResolve = resolve;
    redirectReject = reject;
  });

  const redirectRouter = express.Router();
  redirectRouter.get("/", (req, res) => {
    const token = req.query as T;
    complete(value, token)
      .then((result) => {
        res.status(200).sendFile(`${ROOT_PATH}/public/redirect-landing.html`);
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
