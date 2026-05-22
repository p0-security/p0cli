/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchCommand } from "../../drivers/api.js";
import { Authn } from "../../types/identity.js";

export type Suggestion = {
  key: string;
  value: string;
  group?: string;
};

type LsResponse = {
  ok: true;
  items: {
    key: string;
    value: string;
    group?: string;
    isPreexisting?: boolean;
  }[];
  isTruncated: boolean;
  term: string;
  arg: string;
};

const DEFAULT_LIMIT = 25;

/**
 * Queries the backend's `ls` command for workflow-field suggestions.
 * This is the same listing infrastructure `p0 ls <integration> ...`
 * uses non-interactively, so workflow dropdowns reflect exactly the
 * resources the user could reach via the explicit CLI.
 *
 * `listerArgv` is the integration-specific tail (e.g. `["ssh",
 * "session", "destination"]`); the user's `query` is appended as the
 * final positional so the backend can server-side filter.
 *
 * `dependsOn` maps companion form-field values into `--<flag> <value>`
 * options on the lister call (e.g. the k8s role lister needs
 * `--cluster <id>`). Entries with empty values are dropped — the
 * lister sees no filter for that flag.
 */
export const fetchWorkflowSuggestions = async (
  authn: Authn,
  listerArgv: string[],
  query: string,
  options?: {
    debug?: boolean;
    limit?: number;
    signal?: AbortSignal;
    dependsOn?: { flag: string; value: string }[];
  }
): Promise<Suggestion[]> => {
  const trimmed = query.trim();
  const limit = options?.limit ?? DEFAULT_LIMIT;
  const dependsOn = (options?.dependsOn ?? []).filter(
    (d) => d.value.length > 0
  );
  const argv = [
    "ls",
    ...listerArgv,
    ...(trimmed ? [trimmed] : []),
    ...dependsOn.flatMap((d) => [`--${d.flag}`, d.value]),
    "--size",
    String(limit),
  ];

  // Reuse the existing `p0 ls` POST /command/ wiring — same shape, same
  // authentication, same backend handler. The yargs `args` parameter
  // is only used for $0 / debug; supply a minimal stub.
  const stubArgs = {
    $0: "p0",
    _: [],
    debug: options?.debug,
  } as Parameters<typeof fetchCommand>[1];

  let data: LsResponse;
  try {
    data = await fetchCommand<LsResponse>(authn, stubArgs, argv);
  } catch {
    return [];
  }
  if (!data || !("ok" in data) || !data.ok) return [];
  return data.items.map(({ key, value, group }) => ({ key, value, group }));
};
