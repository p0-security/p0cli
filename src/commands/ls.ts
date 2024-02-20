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
    print2(
      `Showing${
        data.isTruncated ? ` the first ${data.items.length}` : ""
      } ${pluralize(data.arg)}${data.term ? ` matching '${data.term}'` : ""}:`
    );
    for (const item of data.items) {
      print1(item);
    }
  } else {
    throw data;
  }
};
