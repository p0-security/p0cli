/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchCommand } from "../drivers/api";
import { authenticate } from "../drivers/auth";
import { fsShutdownGuard } from "../drivers/firestore";
import { print2 } from "../drivers/stdio";
import { AllowResponse } from "../types/allow";
import { Authn } from "../types/identity";
import yargs from "yargs";

const allowArgs = <T>(yargs: yargs.Argv<T>) =>
  yargs
    .parserConfiguration({ "unknown-options-as-args": true })
    .help(false) // Turn off help in order to forward the --help command to the backend so P0 can provide the available requestable resources
    .option("wait", {
      alias: "w",
      boolean: true,
      default: false,
      describe: "Block until the command is completed",
    })
    .option("arguments", {
      array: true,
      string: true,
      default: [] as string[],
    });

export const allowCommand = (yargs: yargs.Argv) =>
  yargs.command<{ arguments: string[] }>(
    "allow [arguments..]",
    "Create standing access for a resource",
    allowArgs,
    fsShutdownGuard(allow)
  );

export const allow = async (
  args: yargs.ArgumentsCamelCase<{
    arguments: string[];
    wait?: boolean;
  }>,
  authn?: Authn
): Promise<AllowResponse | undefined> => {
  const resolvedAuthn = authn ?? (await authenticate());
  const data = await fetchCommand<AllowResponse>(resolvedAuthn, args, [
    "allow",
    ...args.arguments,
  ]);

  if (data && "ok" in data && "message" in data && data.ok) {
    print2(data.message);
    return data;
  } else {
    throw data;
  }
};
