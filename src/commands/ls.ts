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
import pluralize from "pluralize";
import yargs from "yargs";

type LsResponse = {
  ok: true;
  items: string[];
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

  if (data && "ok" in data && data.ok) {
    const label = pluralize(data.arg);
    if (data.items.length === 0) {
      print2(`No ${label}`);
      return;
    }
    print2(
      `Showing${
        data.isTruncated ? ` the first ${data.items.length}` : ""
      } ${label}${data.term ? ` matching '${data.term}'` : ""}:`
    );
    for (const item of data.items) {
      print1(item);
    }
  } else {
    throw data;
  }
};
