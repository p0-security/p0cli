/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { AnsiSgr } from "../drivers/ansi";
import { fetchCommand } from "../drivers/api";
import { authenticate } from "../drivers/auth";
import { fsShutdownGuard } from "../drivers/firestore";
import { print2, print1, spinUntil } from "../drivers/stdio";
import { max, orderBy } from "lodash";
import pluralize from "pluralize";
import yargs from "yargs";

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

const lsArgs = <T>(yargs: yargs.Argv<T>) =>
  yargs
    .parserConfiguration({ "unknown-options-as-args": true })
    .help(false)
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
    fsShutdownGuard(ls)
  );

const ls = async (
  args: yargs.ArgumentsCamelCase<{
    arguments: string[];
  }>
) => {
  const authn = await authenticate();
  const data = await spinUntil(
    "Listing accessible resources",
    fetchCommand<LsResponse>(authn, args, ["ls", ...args.arguments])
  );
  const allArguments = [...args._, ...args.arguments];

  if (data && "ok" in data && data.ok) {
    const label = pluralize(data.arg);
    if (data.items.length === 0) {
      print2(`No ${label}`);
      return;
    }
    const truncationPart = data.isTruncated
      ? ` the first ${data.items.length}`
      : "";
    const postfixPart = data.term
      ? ` matching '${data.term}'`
      : data.isTruncated
        ? ` (use \`p0
         ${allArguments.join(" ")} <like>\` to narrow results)`
        : "";

    print2(
      `Showing${truncationPart} ${label}${postfixPart}. Resources labeled with * are already accessible to you:`
    );
    const sortedItems = orderBy(data.items, "isPreexisting", "desc");
    const isSameValue = sortedItems.every((i) => !i.group && i.key === i.value);
    const maxLength = max(sortedItems.map((i) => i.key.length)) || 0;
    for (const item of sortedItems) {
      const tagPart = `${item.group ? `${item.group} / ` : ""}${item.value}`;
      const prefix = item.isPreexisting ? "* " : "  ";
      print1(
        `${prefix}${
          isSameValue
            ? item.key
            : maxLength > 30
              ? `${item.key}\n  ${AnsiSgr.Dim}${tagPart}${AnsiSgr.Reset}`
              : `${item.key.padEnd(maxLength)}${AnsiSgr.Dim} - ${tagPart}${AnsiSgr.Reset}`
        }`
      );
    }
  } else {
    throw data;
  }
};
