/** Copyright © 2024-present P0 Security

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print1, print2 } from "../../../drivers/stdio";
import { isa } from "../../../types";
import { compact } from "lodash";
import { spawn } from "node:child_process";
import os from "node:os";
import { sys } from "typescript";
import which from "which";

const SupportedPlatforms = ["darwin"] as const;
type SupportedPlatform = (typeof SupportedPlatforms)[number];

const AwsItems = ["aws", "session-manager-plugin"] as const;
type AwsItem = (typeof AwsItems)[number];

const AwsInstall: Readonly<
  Record<
    AwsItem,
    { label: string; commands: Record<SupportedPlatform, Readonly<string[]>> }
  >
> = {
  aws: {
    label: "AWS CLI v2",
    commands: {
      darwin: [
        'curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"',
        "sudo installer -pkg AWSCLIV2.pkg -target /",
        'rm "AWSCLIV2.pkg"',
      ],
    },
  },
  "session-manager-plugin": {
    label: "the AWS CLI Session Manager plugin",
    commands: {
      darwin: [
        'curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/mac/session-manager-plugin.pkg" -o "session-manager-plugin.pkg"',
        "sudo installer -pkg session-manager-plugin.pkg -target /",
        "sudo ln -s /usr/local/sessionmanagerplugin/bin/session-manager-plugin /usr/local/bin/session-manager-plugin",
        'rm "session-manager-plugin.pkg"',
      ],
    },
  },
};

const printToInstall = (toInstall: AwsItem[]) => {
  print2("The following items must be installed on your system to continue:");
  for (const item of toInstall) {
    print2(`  - ${AwsInstall[item].label}`);
  }
  print2("");
};

const queryInteractive = async () => {
  const inquirer = (await import("inquirer")).default;
  const { isGuided } = await inquirer.prompt([
    {
      type: "confirm",
      name: "isGuided",
      message:
        "Do you want P0 to install these for you (sudo access required)?",
    },
  ]);
  print2("");
  return isGuided;
};

const requiredInstalls = async () =>
  compact(
    await Promise.all(
      AwsItems.map(async (item) =>
        (await which(item, { nothrow: true })) === null ? item : undefined
      )
    )
  );

const printInstallCommands = (platform: SupportedPlatform, item: AwsItem) => {
  const { label, commands } = AwsInstall[item];
  print2(`To install ${label}, run the following commands:\n`);
  for (const command of commands[platform]) {
    print1(`  ${command}`);
  }
  print1(""); // Newline is useful for reading command output in a script, so send to /fd/1
};

const guidedInstall = async (platform: SupportedPlatform, item: AwsItem) => {
  const commands = AwsInstall[item].commands[platform];

  const combined = commands.join(" && \\\n");

  print2(`Executing:\n${combined}`);
  print2("");

  await new Promise<void>((resolve, reject) => {
    const child = spawn("bash", ["-c", combined], { stdio: "inherit" });
    child.on("exit", (code) => {
      if (code === 0) resolve();
      else reject(`Shell exited with code ${code}`);
    });
  });

  print2("");
};

/** Ensures that AWS CLI and SSM plugin are installed on the user environment
 *
 * If they are not, and the session is a TTY, prompt the user to auto-install. If
 * the user declines, or if not a TTY, the installation commands are printed to
 * stdout.
 */
export const ensureSsmInstall = async () => {
  const platform = os.platform();

  if (!isa(SupportedPlatforms)(platform))
    throw "SSH to AWS managed instances is only available on MacOS";

  const toInstall = await requiredInstalls();
  if (toInstall.length === 0) return true;

  printToInstall(toInstall);

  const interactive = !!sys.writeOutputIsTTY?.() && (await queryInteractive());

  for (const item of toInstall) {
    if (interactive) await guidedInstall(platform, item);
    else printInstallCommands(platform, item);
  }

  const remaining = await requiredInstalls();

  if (remaining.length === 0) {
    print2("All packages successfully installed");
    return true;
  }
  return false;
};
