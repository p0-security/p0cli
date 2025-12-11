/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { sanitizeAsFileName } from "../common/destination";
import { authenticate } from "../drivers/auth";
import { print2 } from "../drivers/stdio";
import { sshProxy } from "../plugins/ssh";
import { P0_PATH } from "../util";
import { SSH_PROVIDERS, SshProxyCommandArgs } from "./shared/ssh";
import { cleanupStaleSshConfigs } from "./shared/ssh-cleanup";
import * as fs from "fs/promises";
import path from "path";
import yargs from "yargs";

export const sshProxyCommand = (yargs: yargs.Argv) =>
  yargs.command<SshProxyCommandArgs>(
    "ssh-proxy <destination>",
    false,
    (yargs) =>
      yargs
        .positional("destination", {
          type: "string",
          demandOption: true,
        })
        .option("port", {
          type: "string",
          demandOption: true,
        })
        .option("provider", {
          requiresArg: true,
          type: "string",
          describe: "The cloud provider where the instance is hosted",
          choices: ["aws", "azure", "gcloud", "self-hosted"],

          demandOption: true,
        })
        .option("identityFile", {
          alias: "i",
          requiresArg: true,
          type: "string",
          describe:
            "Path to the private key file to use for the SSH connection",
          demandOption: true,
        })
        .option("requestJson", {
          requiresArg: true,
          type: "string",
          describe: "JSON string of the SSH request",
          demandOption: true,
        })
        .option("debug", {
          type: "boolean",
          describe: "Print debug information.",
        })
        .usage("$0 ssh-proxy <destination>"),

    sshProxyAction
  );

const sshProxyAction = async (
  args: yargs.ArgumentsCamelCase<SshProxyCommandArgs>
) => {
  // Clean up any stale SSH config files before proceeding
  await cleanupStaleSshConfigs(args.debug);

  // Prefix is required because the backend uses it to determine that this is an AWS request
  const authn = await authenticate(args);

  // TODO(ENG-3142): Azure SSH currently doesn't support specifying a port; throw an error if one is set.
  if (args.provider === "azure" && args.port != "22") {
    throw "Azure SSH does not currently support specifying a port. SSH on the target VM must be listening on the default port 22.";
  }

  const sshProvider = SSH_PROVIDERS[args.provider];

  const requestJson = await fs.readFile(args.requestJson, "utf8");
  const request = JSON.parse(requestJson);

  const privateKey = await fs.readFile(args.identityFile, "utf8");

  // This config file was created by the ssh-resolve command. Use the same sanitization here.
  const configFile = sanitizeAsFileName(args.destination);

  const configLocation = path.join(
    P0_PATH,
    "ssh",
    "configs",
    `${configFile}.config`
  );

  if (args.debug) {
    print2("Deleting request JSON file");
  }
  try {
    await fs.rm(args.requestJson);
  } catch (err) {
    if (args.debug) {
      print2(`Warning: Failed to delete request JSON file: ${String(err)}`);
    }
  }

  if (args.debug) {
    print2("Deleting ssh Config file");
  }
  try {
    await fs.rm(configLocation);
  } catch (err) {
    if (args.debug) {
      print2(`Warning: Failed to delete ssh config file: ${String(err)}`);
    }
  }

  await sshProxy({
    authn,
    cmdArgs: args,
    request,
    requestId: request.requestId,
    privateKey,
    debug: args.debug ?? false,
    sshProvider,
    port: args.port,
  });
};
