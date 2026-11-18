/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print1, print2 } from "../../drivers/stdio";
import {
  claimKey,
  GitSession,
  GitStore,
  readStore,
  repositoryKey,
  updateStore,
} from "./store";
import { GitGrantError, refreshSession } from "./token";

export const SESSION_ENDED_TEXT =
  "P0: your git session has ended. Call the git_setup tool, then run the command it returns.";

// Refresh earlier than expiry, so that a long git command keeps a valid token.
const REFRESH_MARGIN_MS = 5 * 60 * 1000;

const GIT_PATH = /^\/?mcps\/(?<backendId>[^/]+)\/git\/(?<repository>.+?)\/?$/;

export const CREDENTIAL_OPERATIONS = ["get", "store", "erase"] as const;
export type CredentialOperation = (typeof CREDENTIAL_OPERATIONS)[number];

type CredentialRequest = {
  attributes: Map<string, string>;
  capabilities: Set<string>;
};

/** Parses git's credential helper input: `key=value` lines up to a blank
 * line. */
export function parseCredentialRequest(input: string): CredentialRequest {
  const attributes = new Map<string, string>();
  const capabilities = new Set<string>();
  for (const line of input.split("\n")) {
    if (line === "") break;
    const at = line.indexOf("=");
    if (at < 0) continue;
    const key = line.slice(0, at);
    const value = line.slice(at + 1);
    if (key === "capability[]") capabilities.add(value);
    else attributes.set(key, value);
  }
  return { attributes, capabilities };
}

type Target = { serverUrl: string; repository: string };

/** The gateway server and the repository that git asks for, or undefined for
 * a URL that is not a P0 git route. */
function targetOf({ attributes }: CredentialRequest): Target | undefined {
  const protocol = attributes.get("protocol");
  const host = attributes.get("host");
  const { backendId, repository } =
    GIT_PATH.exec(attributes.get("path") ?? "")?.groups ?? {};
  if (!protocol || !host || !backendId || !repository) return undefined;
  return {
    serverUrl: `${protocol}://${host}/mcps/${backendId}`,
    repository: repositoryKey(repository),
  };
}

const sessionIdFor = (store: GitStore, { serverUrl, repository }: Target) =>
  store.claims[claimKey(serverUrl, repository)] ?? store.fallback[serverUrl];

const isFresh = (session: GitSession) =>
  session.accessExpiresAt - Date.now() > REFRESH_MARGIN_MS;

const forgetSession = (store: GitStore, sid: string) => {
  delete store.sessions[sid];
  for (const table of [store.claims, store.fallback]) {
    for (const [key, value] of Object.entries(table)) {
      if (value === sid) delete table[key];
    }
  }
};

/** A fresh session for `sid`, or undefined when the git login has ended. */
async function freshSession(sid: string): Promise<GitSession | undefined> {
  const stored = (await readStore()).sessions[sid];
  if (stored && isFresh(stored)) return stored;
  // Under the lock, a parallel git process may already have refreshed.
  return await updateStore(async (store) => {
    const session = store.sessions[sid];
    if (!session || isFresh(session)) return session;
    try {
      const reply = await refreshSession(session);
      const refreshed: GitSession = {
        ...session,
        accessToken: reply.accessToken,
        accessExpiresAt: reply.accessExpiresAt,
        refreshToken: reply.refreshToken,
      };
      store.sessions[sid] = refreshed;
      return refreshed;
    } catch (error) {
      if (!(error instanceof GitGrantError)) throw error;
      forgetSession(store, sid);
      return undefined;
    }
  });
}

function replyLines(session: GitSession, request: CredentialRequest) {
  const expiry = `password_expiry_utc=${Math.floor(session.accessExpiresAt / 1000)}`;
  const credential = request.capabilities.has("authtype")
    ? [
        "capability[]=authtype",
        "authtype=Bearer",
        `credential=${session.accessToken}`,
      ]
    : ["username=p0", `password=${session.accessToken}`];
  return [...credential, "ephemeral=1", expiry];
}

type OperationHandler = (request: CredentialRequest) => Promise<void>;

const getCredential: OperationHandler = async (request) => {
  const target = targetOf(request);
  if (!target) return;
  const sid = sessionIdFor(await readStore(), target);
  const session = sid ? await freshSession(sid) : undefined;
  if (!session) {
    print2(SESSION_ENDED_TEXT);
    return;
  }
  print1(replyLines(session, request).join("\n"));
};

// git calls erase after the gateway refuses the token. The next get refreshes.
const eraseCredential: OperationHandler = async (request) => {
  const target = targetOf(request);
  const refused =
    request.attributes.get("credential") ?? request.attributes.get("password");
  if (!target || !refused) return;
  await updateStore((store) => {
    const sid = sessionIdFor(store, target);
    const session = sid ? store.sessions[sid] : undefined;
    // An erase for an older token must not stop the current one.
    if (session?.accessToken === refused) session.accessExpiresAt = 0;
  });
};

const operationHandlers: Record<CredentialOperation, OperationHandler> = {
  get: getCredential,
  // The tokens are already stored by `p0 git login` and by refresh.
  store: async () => {},
  erase: eraseCredential,
};

/** Runs one git credential helper operation on git's input. */
export const gitCredential = (operation: CredentialOperation, input: string) =>
  operationHandlers[operation](parseCredentialRequest(input));
