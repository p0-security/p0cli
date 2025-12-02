/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { AnsiSgr } from "../drivers/ansi";
import { fetchAdminLsCommand, fetchCommand } from "../drivers/api";
import { authenticate } from "../drivers/auth";
import { print1, print2, spinUntil } from "../drivers/stdio";
import { getAppName } from "../util";
import { max, orderBy, slice } from "lodash";
import pluralize from "pluralize";
import yargs from "yargs";

const DEFAULT_RESPONSE_SIZE = 15;

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
    })
    .option("size", {
      type: "number",
      default: DEFAULT_RESPONSE_SIZE,
      description: "Number of results to return",
    })
    .option("json", {
      type: "boolean",
      default: false,
      description: "Output in JSON format",
    })
    .option("debug", {
      type: "boolean",
      describe: "Print debug information.",
    });

export const lsCommand = (yargs: yargs.Argv) =>
  yargs.command<{
    arguments: string[];
    json: boolean;
    size: number;
    debug: boolean;
  }>("ls [arguments..]", "List request-command arguments", lsArgs, ls);

const ls = async (
  args: yargs.ArgumentsCamelCase<{
    arguments: string[];
    json: boolean;
    size: number;
    debug: boolean;
  }>
) => {
  const authn = await authenticate();

  const isAdminCommand =
    args.arguments.includes("--all") || args.arguments.includes("--principal");

  const isHelpCommand = args.arguments.includes("--help");

  const command = isAdminCommand ? fetchAdminLsCommand : fetchCommand;

  const allArguments = [
    ...args._,
    ...args.arguments,
    /**
     * If the user has requested a size, replace it with double the requested size,
     * otherwise request double the default.
     *
     * This is done so that we can give the user a sense of the number of results
     * that are not displayed.
     */
    ...(args.size && !isHelpCommand ? ["--size", args.size * 2] : []),
  ].map(String); // make sure all elements are strings to satisfy command line args

  const responsePromise: Promise<LsResponse> = command<LsResponse>(
    authn,
    args,
    allArguments
  );

  const data = await spinUntil("Listing accessible resources", responsePromise);

  if (data && "ok" in data && data.ok) {
    if (args.json) {
      print1(JSON.stringify(data, null, 2));
      return;
    }

    const label = pluralize(data.arg);
    if (data.items.length === 0) {
      print2(`No ${label}`);
      return;
    }
    const truncationPart =
      data.items.length > args.size
        ? ` the first ${args.size} (of ${data.isTruncated ? "many" : data.items.length})`
        : "";
    const postfixPart = data.term
      ? ` matching '${data.term}'`
      : data.isTruncated
        ? ` (use \`${getAppName()} ${allArguments.join(" ")} <like>\` to narrow results)`
        : "";

    print2(
      `Showing${truncationPart} ${label}${postfixPart}.\nResources labeled with * are already accessible to you:`
    );
    const truncated = slice(data.items, 0, args.size);
    const sortedItems = orderBy(truncated, "isPreexisting", "desc");
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
