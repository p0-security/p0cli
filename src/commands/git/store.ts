/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { P0_PATH } from "../../util";
import { hasErrorCode, isRecord, isTokenText } from "./guards";
import { withFileLock } from "./lock";
import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

export type GitSession = {
  /** `https://<gateway>/mcps/<backendId>` */
  serverUrl: string;
  tokenEndpoint: string;
  accessToken: string;
  /** Unix time in milliseconds */
  accessExpiresAt: number;
  refreshToken: string;
};

export type GitStore = {
  /** By Session ID (`sid`) */
  sessions: Record<string, GitSession>;
  /** Session ID by {@link claimKey} */
  claims: Record<string, string>;
  /** Session ID by server URL, for a repository that no Session claims */
  fallback: Record<string, string>;
};

const storeDir = () => path.join(P0_PATH, "git");
const storePath = () => path.join(storeDir(), "sessions.json");

const emptyStore = (): GitStore => ({ sessions: {}, claims: {}, fallback: {} });

/** `owner/repo` in lower case, with one trailing `.git` removed. */
export const repositoryKey = (repository: string) =>
  repository.toLowerCase().replace(/\.git$/, "");

export const claimKey = (serverUrl: string, repository: string) =>
  `${serverUrl}#${repositoryKey(repository)}`;

const isGitSession = (value: unknown): value is GitSession =>
  isRecord(value) &&
  typeof value.serverUrl === "string" &&
  typeof value.tokenEndpoint === "string" &&
  isTokenText(value.accessToken) &&
  typeof value.accessExpiresAt === "number" &&
  isTokenText(value.refreshToken);

const isString = (value: unknown): value is string => typeof value === "string";

const entriesOf = <T>(
  value: unknown,
  isValue: (entry: unknown) => entry is T
): Record<string, T> =>
  isRecord(value)
    ? Object.fromEntries(
        Object.entries(value).filter((entry): entry is [string, T] =>
          isValue(entry[1])
        )
      )
    : {};

const brokenStore = () =>
  `The P0 git token file is not valid. Remove ${storePath()}, then call the git_setup tool again.`;

function parseStore(text: string): GitStore {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw brokenStore();
  }
  if (!isRecord(parsed)) throw brokenStore();
  return {
    sessions: entriesOf(parsed.sessions, isGitSession),
    claims: entriesOf(parsed.claims, isString),
    fallback: entriesOf(parsed.fallback, isString),
  };
}

/** The stored git Sessions; empty when nothing is stored. */
export async function readStore(): Promise<GitStore> {
  try {
    return parseStore(await fs.readFile(storePath(), "utf-8"));
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) return emptyStore();
    throw error;
  }
}

async function writeStore(store: GitStore): Promise<void> {
  // Write a new file and rename it, so that a reader never sees half a file.
  const temp = `${storePath()}.${randomUUID()}.tmp`;
  await fs.writeFile(temp, JSON.stringify(store), { mode: 0o600, flag: "wx" });
  await fs.rename(temp, storePath());
}

/** Runs `fn` on the stored git Sessions under a lock, then stores what `fn`
 * leaves in the store. Use this for every change to the store. */
export async function updateStore<T>(
  fn: (store: GitStore) => Promise<T> | T
): Promise<T> {
  await fs.mkdir(storeDir(), { recursive: true, mode: 0o700 });
  await fs.chmod(storeDir(), 0o700);
  return await withFileLock(`${storePath()}.lock`, async () => {
    const store = await readStore();
    const result = await fn(store);
    await writeStore(store);
    return result;
  });
}
