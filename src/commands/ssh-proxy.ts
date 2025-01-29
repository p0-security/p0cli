import { authenticate } from "../drivers/auth";
import { fsShutdownGuard } from "../drivers/firestore";
import { sshProxy } from "../plugins/ssh";
import { P0_PATH } from "../util";
import { SSH_PROVIDERS, SshProxyCommandArgs } from "./shared/ssh";
import * as fs from "fs/promises";
import path from "path";
import yargs from "yargs";

export const sshProxyCommand = (yargs: yargs.Argv) =>
  yargs.command<SshProxyCommandArgs>(
    "ssh-proxy <destination>",
    "SSH into a virtual machine",
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
          choices: ["aws", "azure", "gcloud"],
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

    fsShutdownGuard(sshProxyAction)
  );

const sshProxyAction = async (
  args: yargs.ArgumentsCamelCase<SshProxyCommandArgs>
) => {
  // Prefix is required because the backend uses it to determine that this is an AWS request
  const authn = await authenticate();

  // TODO(ENG-3142): Azure SSH currently doesn't support specifying a port; throw an error if one is set.
  if (args.provider === "azure" && args.port != "22") {
    throw "Azure SSH does not currently support specifying a port. SSH on the target VM must be listening on the default port 22.";
  }

  const sshProvider = SSH_PROVIDERS[args.provider];

  const requestJson = await fs.readFile(args.requestJson, "utf8");
  const request = JSON.parse(requestJson);

  const privateKey = await fs.readFile(args.identityFile, "utf8");

  const configLocation = path.join(
    P0_PATH,
    "ssh",
    "configs",
    `${args.destination}.config`
  );

  await fs.rm(args.requestJson);
  await fs.rm(configLocation);

  await sshProxy({
    authn,
    cmdArgs: args,
    request,
    privateKey,
    debug: args.debug ?? false,
    sshProvider,
    port: args.port,
  });
};
