/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { login } from "../../commands/login";
import { Authn, Identity } from "../../types/identity";
import { TokenResponse } from "../../types/oidc";
import { OrgData } from "../../types/org";
import { authenticateToFirebase } from "../firestore";
import { print2 } from "../stdio";
import { getIdentityCachePath, getIdentityFilePath } from "./path";
import * as fs from "fs/promises";
import * as os from "os";
import * as path from "path";

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

const loadCredentialsWithAutoLogin = async (options?: {
  noRefresh?: boolean;
}): Promise<Identity> => {
  try {
    const buffer = await fs.readFile(getIdentityFilePath());
    const identity: Identity = JSON.parse(buffer.toString());
    if (
      !options?.noRefresh &&
      identity.credential.expires_at < Date.now() * 1e-3
    ) {
      await login({ org: identity.org.slug }, { skipAuthenticate: true });
      print2("\u200B"); // Force a new line
      return loadCredentialsWithAutoLogin({ noRefresh: true });
    }
    return identity;
  } catch (error: any) {
    if (error?.code === "ENOENT") {
      throw "Please run `p0 login <organization>` to use the P0 CLI.";
    }
    throw error;
  }
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
  await fs.writeFile(
    identityFilePath,
    JSON.stringify(
      {
        credential: { ...credential, expires_at },
        org,
      },
      null,
      2
    ),
    {
      mode: "600",
    }
  );
};

export const deleteIdentity = async () => {
  await clearIdentityCache();
  await clearIdentityFile();
};

export const authenticate = async (options?: {
  noRefresh?: boolean;
}): Promise<Authn> => {
  const identity = await loadCredentialsWithAutoLogin(options);
  const userCredential = await authenticateToFirebase(identity);

  return { userCredential, identity };
};
