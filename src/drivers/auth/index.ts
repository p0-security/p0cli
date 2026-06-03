/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { login } from "../../commands/login";
import { setExporterAfterLogin } from "../../opentelemetry/instrumentation";
import { getProviderType } from "../../types/authUtils";
import { Authn, Identity } from "../../types/identity";
import { TokenResponse } from "../../types/oidc";
import { OrgData } from "../../types/org";
import { getAppName } from "../../util";
import { tracesUrl } from "../api";
import { authenticateToFirebase } from "../firestore";
import { print2 } from "../stdio";
import { getExpiredCredentialsMessage } from "../util";
import { withIdentityLock } from "./lock";
import { getIdentityCachePath, getIdentityFilePath } from "./path";
import { refreshOktaTokens, revokeOktaRefreshToken } from "./refresh";
import * as fs from "fs/promises";
import * as path from "path";

const MIN_REMAINING_TOKEN_TIME_SECONDS = 60;

export const cached = async <T>(
  name: string,
  loader: () => Promise<T>,
  options: { duration: number },
  hasExpired?: (data: T) => boolean
): Promise<T> => {
  const identityCachePath = getIdentityCachePath();

  // Following lines sanitize input
  // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  const loc = path.resolve(path.join(identityCachePath, `${name}.json`));
  if (!loc.startsWith(identityCachePath)) {
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

const clearIdentityFile = async () => {
  try {
    const identityFilePath = getIdentityFilePath();
    // check to see if the file exists before trying to remove it
    await fs.access(identityFilePath);
    await fs.rm(identityFilePath);
  } catch {
    return;
  }
};

const clearIdentityCache = async () => {
  try {
    const identityCachePath = getIdentityCachePath();
    // check to see if the directory exists before trying to remove it
    await fs.access(identityCachePath);
    await fs.rm(identityCachePath, { recursive: true });
  } catch {
    return;
  }
};

export const loadCredentials = async (): Promise<Identity> => {
  try {
    const buffer = await fs.readFile(getIdentityFilePath());
    const data = JSON.parse(buffer.toString()) as Identity;
    if (!data.org?.auth) {
      throw { code: "LEGACY_IDENTITY", slug: data.org.slug };
    }
    return data;
  } catch (error: any) {
    if (error?.code === "ENOENT") {
      throw `Please run \`${getAppName()} login <organization>\`.`;
    }
    throw error;
  }
};

export const remainingTokenTime = (identity: Identity) =>
  Math.floor(identity.credential.expires_at - Date.now() * 1e-3);

const loadCredentialsWithAutoLogin = async (options?: {
  noRefresh?: boolean;
  debug?: boolean;
}): Promise<Identity> => {
  let identity: Identity;
  try {
    identity = await loadCredentials();
  } catch (e: any) {
    if (e?.code === "LEGACY_IDENTITY") {
      await login(
        { org: e.slug },
        { debug: options?.debug, skipAuthenticate: true }
      );
      print2("\n");
      return loadCredentialsWithAutoLogin({ noRefresh: true });
    }
    throw e;
  }

  if (remainingTokenTime(identity) > MIN_REMAINING_TOKEN_TIME_SECONDS) {
    return identity;
  }

  // If token is expired, and provider is okta, try the silent refresh-token
  // grant first, and only fall through to the interactive device flow if that
  // path is unavailable or fails.
  if (
    identity.credential.refresh_token &&
    getProviderType(identity.org) === "okta"
  ) {
    try {
      return await withIdentityLock(async () => {
        // Double-checked under the lock: a peer process may have refreshed
        // identity.json while we were waiting to acquire it.
        const current = await loadCredentials();
        if (remainingTokenTime(current) > MIN_REMAINING_TOKEN_TIME_SECONDS) {
          return current;
        }
        const refreshed = await refreshOktaTokens(current, {
          debug: options?.debug,
        });
        await writeIdentity(current.org, refreshed);
        return await loadCredentials();
      });
    } catch (e: any) {
      if (options?.debug) {
        const detail = e?.reason ?? e?.code ?? e?.message ?? String(e);
        print2(
          `Okta refresh-token grant failed (${detail}); falling back to device flow.`
        );
      }
    }
  }

  if (options?.noRefresh) {
    throw getExpiredCredentialsMessage();
  }

  await login(
    { org: identity.org.slug },
    { debug: options?.debug, skipAuthenticate: true }
  );
  print2("\u200B"); // Force a new line
  return loadCredentialsWithAutoLogin({ noRefresh: true });
};

export const writeIdentity = async (
  org: OrgData,
  credential: TokenResponse
) => {
  await clearIdentityCache();

  const identityFilePath = getIdentityFilePath();

  const expires_at = Date.now() * 1e-3 + credential.expires_in - 1; // Add 1 second safety margin
  print2(`Saving authorization to ${identityFilePath}.`);
  const dir = path.dirname(identityFilePath);
  await fs.mkdir(dir, { recursive: true });
  // Write to a sibling tmp file then rename, so a crash mid-write can't leave
  // identity.json truncated. Same-directory rename keeps the operation atomic.
  const tmpPath = `${identityFilePath}.tmp`;
  await fs.writeFile(
    tmpPath,
    JSON.stringify({ credential: { ...credential, expires_at }, org }, null, 2),
    { mode: "600" }
  );
  await fs.rename(tmpPath, identityFilePath);
};

export const deleteIdentity = async (options?: { debug?: boolean }) => {
  // Best-effort: revoke the refresh_token at the IDP before destroying our
  // local copy.

  const identity = await loadCredentials();
  if (
    identity.credential.refresh_token &&
    getProviderType(identity.org) === "okta"
  ) {
    await revokeOktaRefreshToken(identity, { debug: options?.debug });
  }

  await clearIdentityCache();
  await clearIdentityFile();
};

/** Set up trace exporter to authenticated collector endpoint */
const setOpentelemetryExporter = async (authn: Authn): Promise<void> => {
  const url = tracesUrl(authn.identity.org.slug);
  await setExporterAfterLogin(url, await authn.getToken());
};

export const authenticate = async (options?: {
  noRefresh?: boolean;
  debug?: boolean;
}): Promise<Authn> => {
  const identity = await loadCredentialsWithAutoLogin(options);
  if (options?.debug) {
    print2(`Loaded identity for user for org ${identity.org.slug}`);
    print2(`Token expires in ${remainingTokenTime(identity)} seconds`);
  }
  let authn: Authn;

  if (identity.org.useProviderToken) {
    authn = {
      identity,
      getToken: () => Promise.resolve(identity.credential.access_token),
    };
  } else {
    // Note: if the `providerId` is "password", we've actually already
    // retrieved the UserCredential object in `loadCredentialsWithAutoLogin`.
    // This following call to `authenticateToFirebase` could be omitted.
    const userCredential = await authenticateToFirebase(identity, options);
    authn = {
      identity,
      userCredential,
      getToken: () => userCredential.user.getIdToken(),
    };
  }

  await setOpentelemetryExporter(authn);
  return authn;
};
