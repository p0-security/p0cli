/** Implements a local auth server, which can receive auth tokens from an OIDC app */
import { sleep } from "../../util";
import express from "express";
import http from "node:http";
import { dirname } from "node:path";

const ROOT_PATH = dirname(require.main!.filename);

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
  let server: http.Server;
  const redirectPromise = new Promise<U>((resolve, reject) => {
    redirectResolve = resolve;
    redirectReject = reject;
  });

  const redirectRouter = express.Router();
  redirectRouter.get("/", (req, res) => {
    const token = req.query as T;
    complete(value, token)
      .then((result) => {
        // res.redirect(`${ROOT_PATH}/redirect-landing.html`);
        res.status(200).sendFile(`${ROOT_PATH}/public/redirect-landing.html`);
        redirectResolve(result);
      })
      .catch((error: any) => {
        res.status(500).send(error?.message ?? error);
        redirectReject(error);
      });
  });

  app.use(redirectRouter);

  server = app.listen(options?.port ?? 0);

  try {
    value = await start(server);
    return await redirectPromise;
  } finally {
    await sleep(2000);
    server.closeAllConnections();
    server.unref();
  }
};
