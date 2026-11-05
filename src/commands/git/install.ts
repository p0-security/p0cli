/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { asyncSpawn } from "../../common/subprocess";
import { print1, print2 } from "../../drivers/stdio";
import { normalizeServerUrl } from "./server-url";

// Rewrite SSH URLs too. Then git cannot use a local SSH key to go around P0.
const GITHUB_URLS = [
  "https://github.com/",
  "http://github.com/",
  "git://github.com/",
  "git@github.com:",
  "ssh://git@github.com/",
  "ssh://github.com/",
] as const;

const HELPER = "!p0 git credential";

export type GitConfigEntry = { key: string; value: string };

/** The git config that sends github.com remotes to the gateway's git route. */
export function gitConfigEntries(serverUrl: string): GitConfigEntry[] {
  const server = normalizeServerUrl(serverUrl);
  const { origin } = new URL(server);
  return [
    ...GITHUB_URLS.map((value) => ({
      key: `url.${server}/git/.insteadOf`,
      value,
    })),
    // An empty helper removes the helpers set before it, so that no other
    // helper stores the P0 token.
    { key: `credential.${origin}.helper`, value: "" },
    { key: `credential.${origin}.helper`, value: HELPER },
    { key: `credential.${origin}.useHttpPath`, value: "true" },
  ];
}

/** The entries as `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` and
 * `GIT_CONFIG_VALUE_<n>` variables. */
export function gitConfigEnv(
  entries: GitConfigEntry[]
): Record<string, string> {
  return Object.fromEntries([
    ["GIT_CONFIG_COUNT", String(entries.length)],
    ...entries.flatMap(({ key, value }, index) => [
      [`GIT_CONFIG_KEY_${index}`, key],
      [`GIT_CONFIG_VALUE_${index}`, value],
    ]),
  ]);
}

const shellQuote = (value: string) => `'${value.replace(/'/g, `'\\''`)}'`;

async function writeGlobal(entries: GitConfigEntry[]) {
  for (const key of new Set(entries.map((entry) => entry.key))) {
    // The unset fails when the key is not set.
    await asyncSpawn({}, "git", [
      "config",
      "--global",
      "--unset-all",
      key,
    ]).catch(() => {});
  }
  for (const { key, value } of entries) {
    await asyncSpawn({}, "git", ["config", "--global", "--add", key, value]);
  }
}

export type GitInstallArgs = {
  serverUrl: string;
  global: boolean;
  json: boolean;
};

/** Prints the git config for the agent's environment, or writes it to
 * `~/.gitconfig` with `global`. */
export async function gitInstall({ serverUrl, global, json }: GitInstallArgs) {
  const entries = gitConfigEntries(serverUrl);
  if (global) {
    await writeGlobal(entries);
    print2("Wrote the P0 git config to ~/.gitconfig.");
    return;
  }
  const env = gitConfigEnv(entries);
  print1(
    json
      ? JSON.stringify(env, null, 2)
      : Object.entries(env)
          .map(([name, value]) => `export ${name}=${shellQuote(value)}`)
          .join("\n")
  );
}
