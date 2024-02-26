/** Copyright © 2024-present P0 Security

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchCommand } from "../drivers/api";
import { authenticate } from "../drivers/auth";
import { guard } from "../drivers/firestore";
import { print2, print1 } from "../drivers/stdio";
import { max } from "lodash";
import pluralize from "pluralize";
import yargs from "yargs";

type LsResponse = {
  ok: true;
  items: { key: string; value: string; group?: string }[];
  isTruncated: boolean;
  term: string;
  arg: string;
};

const lsArgs = <T>(yargs: yargs.Argv<T>) =>
  yargs
    .parserConfiguration({ "unknown-options-as-args": true })
    .option("arguments", {
      array: true,
      string: true,
      default: [] as string[],
    });

export const lsCommand = (yargs: yargs.Argv) =>
  yargs.command<{ arguments: string[] }>(
    "ls [arguments..]",
    "List request-command arguments",
    lsArgs,
    guard(ls)
  );

const ls = async (
  args: yargs.ArgumentsCamelCase<{
    arguments: string[];
  }>
) => {
  const authn = await authenticate();
  const data = await fetchCommand<LsResponse>(authn, args, [
    "ls",
    ...args.arguments,
  ]);
  const allArguments = [...args._, ...args.arguments];

  if (data && "ok" in data && data.ok) {
    const truncationPart = data.isTruncated
      ? ` the first ${data.items.length}`
      : "";
    const argPart = pluralize(data.arg);
    const postfixPart = data.term
      ? ` matching '${data.term}'`
      : data.isTruncated
        ? ` (use \`p0
         ${allArguments.join(" ")} <like>\` to narrow results)`
        : "";

    print2(`Showing${truncationPart} ${argPart}${postfixPart}:`);
    const isSameValue = data.items.every((i) => !i.group && i.key === i.value);
    const longest = max(data.items.map((i) => i.key.length)) || 0;
    for (const item of data.items) {
      print1(
        isSameValue ? item.key : `${item.key.padEnd(longest)} - ${item.value}`
      );
    }
  } else {
    throw data;
  }
};
