/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { login } from "../commands/login";
import { Authn, Identity } from "../types/identity";
import { P0_PATH } from "../util";
import { auth } from "./firestore";
import { print2 } from "./stdio";
import {
  OAuthProvider,
  SignInMethod,
  signInWithCredential,
} from "firebase/auth";
import * as fs from "fs/promises";
import * as path from "path";

export const IDENTITY_FILE_PATH = path.join(P0_PATH, "identity.json");

export const cached = async <T>(
  name: string,
  loader: () => Promise<T>,
  options: { duration: number },
  hasExpired?: (data: T) => boolean
): Promise<T> => {
  const cachePath = path.join(path.dirname(IDENTITY_FILE_PATH), "cache");
  // Following lines sanitize input
  // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  const loc = path.resolve(path.join(cachePath, `${name}.json`));
  if (!loc.startsWith(cachePath)) {
    throw new Error("Illegal path traversal");
  }

  const loadCache = async () => {
    const data = await loader();
    if (!data) throw `Could not load credentials for "${name}"`;
    await fs.mkdir(path.dirname(loc), { recursive: true, mode: "700" });
    await fs.writeFile(loc, JSON.stringify(data), { mode: "600" });
    return data;
  };

  try {
    const stat = await fs.stat(loc);
    if (stat.mtime.getTime() < Date.now() - options.duration) {
      await fs.rm(loc);
      return await loadCache();
    }

    const data = JSON.parse((await fs.readFile(loc)).toString("utf-8")) as T;
    if (hasExpired?.(data)) {
      await fs.rm(loc);
      return await loadCache();
    }
    return data;
  } catch (error: any) {
    if (error?.code !== "ENOENT")
      print2(
        `Could not load credentials "${name}" from cache: ${error.message ?? error}`
      );
    return await loadCache();
  }
};

export const loadCredentials = async (options?: {
  noRefresh?: boolean;
}): Promise<Identity> => {
  try {
    const buffer = await fs.readFile(IDENTITY_FILE_PATH);
    const identity: Identity = JSON.parse(buffer.toString());
    if (
      !options?.noRefresh &&
      identity.credential.expires_at < Date.now() * 1e-3
    ) {
      await login({ org: identity.org.slug }, { skipAuthenticate: true });
      print2("\u200B"); // Force a new line
      return loadCredentials({ noRefresh: true });
    }
    return identity;
  } catch (error: any) {
    if (error?.code === "ENOENT") {
      throw "Please run `p0 login <organization>` to use the P0 CLI.";
    }
    throw error;
  }
};

export const authenticate = async (options?: {
  noRefresh?: boolean;
}): Promise<Authn> => {
  const identity = await loadCredentials(options);
  const { credential } = identity;

  // TODO: Move to map lookup
  const provider = new OAuthProvider(
    identity.org.ssoProvider === "google"
      ? SignInMethod.GOOGLE
      : identity.org.providerId
  );
  const firebaseCredential = provider.credential({
    accessToken: credential.access_token,
    idToken: credential.id_token,
  });
  auth.tenantId = identity.org.tenantId;
  const userCredential = await signInWithCredential(auth, firebaseCredential);

  return { userCredential, identity };
};
