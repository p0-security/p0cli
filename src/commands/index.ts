/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { getHelpMessage } from "../drivers/config";
import { print1, print2 } from "../drivers/stdio";
import { checkVersion } from "../middlewares/version";
import { p0VersionInfo } from "../version";
import { allowCommand } from "./allow";
import { awsCommand } from "./aws";
import { grantCommand } from "./grant";
import { kubeconfigCommand } from "./kubeconfig";
import { loginCommand } from "./login";
import { lsCommand } from "./ls";
import { requestCommand } from "./request";
import { scpCommand } from "./scp";
import { sshCommand } from "./ssh";
import { sshKeyGenCommand } from "./ssh-keygen";
import { sshProxyCommand } from "./ssh-proxy";
import { sshResolveCommand } from "./ssh-resolve";
import { sys } from "typescript";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

const commands = [
  awsCommand,
  grantCommand,
  loginCommand,
  lsCommand,
  requestCommand,
  allowCommand,
  sshCommand,
  sshProxyCommand,
  sshResolveCommand,
  scpCommand,
  sshKeyGenCommand,
  kubeconfigCommand,
];

const buildArgv = async () => {
  const { version } = await p0VersionInfo;
  const argv = yargs(hideBin(process.argv)).version(version);

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

// Skip the version check for these non-interactive commands
const skipVersionCheckFor = ["ssh-proxy", "ssh-resolve"];

function conditionalCheckVersion(argv: yargs.ArgumentsCamelCase) {
  const invokedCommand = argv._[0];

  if (typeof invokedCommand !== "string") {
    return;
  }

  if (skipVersionCheckFor.includes(invokedCommand)) {
    return;
  } else {
    return checkVersion(argv);
  }
}

export const getCli = async () =>
  commands
    .reduce((m, c) => c(m), await buildArgv())
    .middleware(conditionalCheckVersion)
    .strict()
    .demandCommand(1)
    .fail((message, error, yargs) => {
      if (error) {
        print2(error);
      } else {
        print2(yargs.help());
        print2(`\n${message}`);
        print2(`\n${getHelpMessage()}`);
      }
      sys.exit(1);
    });
