/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { getHelpMessage } from "../drivers/config";
import { print1, print2 } from "../drivers/stdio";
import { runInteractive } from "../interactive";
import { checkVersion } from "../middlewares/version";
import { exitProcess, markSpanError } from "../opentelemetry/otel-helpers";
import { p0VersionInfo, stringifyVersionInfo } from "../version";
import { allowCommand } from "./allow";
import { awsCommand } from "./aws";
import { claudeCommand } from "./claude";
import { fileTransferCommand } from "./file-transfer";
import { grantCommand } from "./grant";
import { kubeconfigCommand } from "./kubeconfig";
import { loginCommand } from "./login";
import { logoutCommand } from "./logout";
import { lsCommand } from "./ls";
import { printBearerTokenCommand } from "./print-bearer-token";
import { rdpCommand } from "./rdp";
import { requestCommand } from "./request";
import { scpCommand } from "./scp";
import { sshCommand } from "./ssh";
import { sshProxyCommand } from "./ssh-proxy";
import { sshResolveCommand } from "./ssh-resolve";
import { trace } from "@opentelemetry/api";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

const commands = [
  awsCommand,
  claudeCommand,
  grantCommand,
  loginCommand,
  logoutCommand,
  lsCommand,
  requestCommand,
  allowCommand,
  sshCommand,
  sshProxyCommand,
  sshResolveCommand,
  scpCommand,
  rdpCommand,
  kubeconfigCommand,
  printBearerTokenCommand,
  fileTransferCommand,
];

const buildArgv = async () => {
  const argv = yargs(hideBin(process.argv)).version(
    stringifyVersionInfo(p0VersionInfo)
  );

  // Override the default yargs showHelp() function to include a custom help message at the end
  const originalShowHelp = argv.showHelp.bind(argv);
  argv.showHelp = (arg?: string | ((s: string) => void)) => {
    if (typeof arg === "function") {
      originalShowHelp((s) => arg(s + "\n" + getHelpMessage()));
    } else {
      originalShowHelp(arg);
      print1(`\n${getHelpMessage()}`);
    }

    return argv;
  };

  return argv;
};

const withInteractiveEntry = (argv: yargs.Argv) =>
  argv
    .option("interactive", {
      alias: "i",
      type: "boolean",
      default: false,
      describe: "Open the interactive main menu",
    })
    .command(
      "$0",
      "Open the interactive main menu (when -i / --interactive is set)",
      {},
      async (args) => {
        if (args.interactive) {
          await runInteractive({
            entry: "menu",
            debug: Boolean(args.debug),
          });
          return;
        }
        argv.showHelp();
        exitProcess(1);
      }
    );

// Skip the version check for these non-interactive commands
const skipVersionCheckFor = ["ssh-proxy", "ssh-resolve"];

async function conditionalCheckVersion(argv: yargs.ArgumentsCamelCase) {
  const invokedCommand = argv._[0];

  if (typeof invokedCommand !== "string") {
    return;
  }

  if (skipVersionCheckFor.includes(invokedCommand)) {
    return;
  } else {
    return await checkVersion(argv);
  }
}

export const getCli = async () =>
  withInteractiveEntry(commands.reduce((m, c) => c(m), await buildArgv()))
    .middleware(conditionalCheckVersion)
    .strict()
    .fail((message, error, yargs) => {
      // Mark active span as error if it exists
      // Wrapped in try/catch - telemetry must never break the CLI
      try {
        const activeSpan = trace.getActiveSpan();
        if (activeSpan) {
          const errorMessage = error ? String(error) : message;
          markSpanError(activeSpan, errorMessage);
        }
      } catch (e) {
        // Silently ignore telemetry failures
        // CLI functionality takes precedence over observability
      }

      // Print error messages (existing behavior)
      if (error) {
        print2(error);
      } else {
        print2(yargs.help());
        print2(`\n${message}`);
        print2(`\n${getHelpMessage()}`);
      }

      // Use exitProcess instead of sys.exit for consistent span handling
      exitProcess(1);
    });
