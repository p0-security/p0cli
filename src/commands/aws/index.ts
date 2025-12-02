/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authenticate } from "../../drivers/auth";
import { print2 } from "../../drivers/stdio";
import { observedExit } from "../../opentelemetry/otel-helpers";
import { getFirstAwsConfig } from "../../plugins/aws/config";
import { permissionSet } from "./permission-set";
import { role } from "./role";
import { SpanStatusCode, trace } from "@opentelemetry/api";
import { sys } from "typescript";
import yargs from "yargs";

const awsArgs = async (yargs: yargs.Argv) => {
  try {
    const authn = await authenticate();

    const { config } = await getFirstAwsConfig(authn);

    const base = yargs
      // This parent command hangs without a handler, if we require at
      // least 1 arg we'll always correctly display a help message.
      .demandCommand(1)
      .option("account", {
        type: "string",
        describe: "AWS account ID or alias (or set P0_AWS_ACCOUNT)",
      })
      .option("reason", {
        describe: "Reason access is needed",
        type: "string",
      })
      .option("debug", {
        type: "boolean",
        describe: "Print debug information.",
      })
      .env("P0_AWS");

    const withCommand =
      config.login?.type === "idc"
        ? permissionSet(base, authn)
        : role(base, authn);
    return withCommand;
  } catch (error) {
    // Handle authentication errors here, since
    // this occurs during command building

    print2(error);
    observedExit(1, error);
    throw error; // This will never be reached, but is needed to satisfy TypeScript
  }
};

export const awsCommand = (yargs: yargs.Argv) =>
  yargs.command("aws", "Execute AWS commands", awsArgs);
