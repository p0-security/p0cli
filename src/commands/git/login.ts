/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { normalizeServerUrl } from "./server-url";
import { claimKey, updateStore } from "./store";
import {
  discoverTokenEndpoint,
  GitGrantError,
  redeemSetupCode,
  sessionIdOf,
} from "./token";

export type GitLoginArgs = { serverUrl: string; code: string };

/** Redeems a Setup code from the `git_setup` tool. Afterwards, git uses this
 * Session for its Grant repositories and for repositories that no Session
 * claims. */
export async function gitLogin({ serverUrl, code }: GitLoginArgs) {
  const server = normalizeServerUrl(serverUrl);
  const tokenEndpoint = await discoverTokenEndpoint(server);
  const reply = await redeemSetupCode(tokenEndpoint, code).catch((error) => {
    if (error instanceof GitGrantError) {
      throw "The code is not valid. It works once and expires after 60 seconds. Call the git_setup tool again.";
    }
    throw error;
  });
  const sid = sessionIdOf(reply.accessToken);
  await updateStore((store) => {
    store.sessions[sid] = {
      serverUrl: server,
      tokenEndpoint,
      accessToken: reply.accessToken,
      accessExpiresAt: reply.accessExpiresAt,
      refreshToken: reply.refreshToken,
    };
    for (const repository of reply.repositories) {
      store.claims[claimKey(server, repository)] = sid;
    }
    store.fallback[server] = sid;
  });
  const repositories = reply.repositories.join(", ") || "none yet";
  print2(
    `git is set up for this session. Repositories with a Grant: ${repositories}.`
  );
}
