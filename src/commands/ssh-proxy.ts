import { authenticate } from "../drivers/auth";
import { fsShutdownGuard } from "../drivers/firestore";
import { sshProxy } from "../plugins/ssh";
import { SshProxyCommandArgs, prepareRequest } from "./shared/ssh";
import yargs from "yargs";

export const sshProxyCommand = (yargs: yargs.Argv) =>
  yargs.command<SshProxyCommandArgs>(
    "ssh-proxy <destination> <port>",
    "SSH into a virtual machine",
    (yargs) =>
      yargs
        .positional("destination", {
          type: "string",
          demandOption: true,
        })
        .positional("port", {
          type: "string",
          demandOption: true,
        })
        .option("sudo", {
          type: "boolean",
          describe: "Add user to sudoers file",
        })
        // Match `p0 request --reason`
        .option("reason", {
          describe: "Reason access is needed",
          type: "string",
        })
        .option("parent", {
          type: "string",
          describe:
            "The containing parent resource which the instance belongs to (account, project, subscription, etc.)",
        })
        .option("provider", {
          type: "string",
          describe: "The cloud provider where the instance is hosted",
          choices: ["aws", "azure", "gcloud"],
        })
        .option("debug", {
          type: "boolean",
          describe: "Print debug information.",
        })
        .option("proxy-command", {
          type: "boolean",
          describe: "Use p0 as a proxy command", // TODO improve this
        })
        .usage("$0 ssh-proxy <destination> <port> [command [arguments..]]"),

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

  const { request, privateKey, sshProvider } = await prepareRequest(
    authn,
    args,
    args.destination
  );

  await sshProxy({
    authn,
    request,
    cmdArgs: args,
    privateKey,
    sshProvider,
    port: args.port,
  });
};
