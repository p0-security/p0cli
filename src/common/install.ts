/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print1, print2 } from "../drivers/stdio";
import { isa } from "../types";
import { spawnWithCleanEnv } from "../util";
import { compact } from "lodash";
import os from "node:os";
import { sys } from "typescript";
import which from "which";

export const SupportedPlatforms = ["darwin"] as const;
export type SupportedPlatform = (typeof SupportedPlatforms)[number];

export const AwsItems = ["aws"] as const;
export type AwsItem = (typeof AwsItems)[number];

export const HomebrewItems = ["brew"] as const;
export type HomebrewItem = (typeof HomebrewItems)[number];

export type InstallMetadata = {
  label: string;
  commands: Record<SupportedPlatform, Readonly<string[]>>;
};

export const AwsInstall: Readonly<Record<AwsItem, InstallMetadata>> = {
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
};

export const HomebrewInstall: Readonly<Record<HomebrewItem, InstallMetadata>> =
  {
    brew: {
      label: "Homebrew",
      commands: {
        darwin: [
          '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
        ],
      },
    },
  };

const printToInstall = <
  T extends string,
  U extends Readonly<Record<T, InstallMetadata>>,
>(
  toInstall: readonly T[],
  installMetadata: U
) => {
  print2("The following items must be installed on your system to continue:");
  for (const item of toInstall) {
    print2(`  - ${installMetadata[item].label} (${item})`);
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
        "Do you want to install these automatically? (sudo access required)",
    },
  ]);
  print2("");
  return isGuided;
};

const requiredInstalls = async <T extends string>(installItems: readonly T[]) =>
  compact(
    await Promise.all(
      installItems.map(async (item) =>
        (await which(item, { nothrow: true })) === null ? item : undefined
      )
    )
  );

const printInstallCommands = <
  T extends string,
  U extends Readonly<Record<T, InstallMetadata>>,
>(
  platform: SupportedPlatform,
  item: T,
  installData: U
) => {
  const { label, commands } = installData[item];
  print2(`To install ${label}, run the following commands:\n`);
  for (const command of commands[platform]) {
    print1(`  ${command}`);
  }
  print1(""); // Newline is useful for reading command output in a script, so send to /fd/1
};

export const guidedInstall = async <
  T extends string,
  U extends Readonly<Record<T, InstallMetadata>>,
>(
  platform: SupportedPlatform,
  item: T,
  installData: U
) => {
  const commands = installData[item].commands[platform];

  const combined = commands.join(" && \\\n");

  print2(`Executing:\n${combined}`);
  print2("");

  await new Promise<void>((resolve, reject) => {
    const child = spawnWithCleanEnv("bash", ["-c", combined], {
      stdio: "inherit",
    });
    child.on("exit", (code) => {
      if (code === 0) resolve();
      else reject(`Shell exited with code ${code}`);
    });
  });

  print2("");
};

export const ensureInstall = async <
  T extends string,
  U extends Readonly<Record<T, InstallMetadata>>,
>(
  installItems: readonly T[],
  installData: U
): Promise<boolean> => {
  const toInstall = await requiredInstalls(installItems);

  if (toInstall.length === 0) {
    return true;
  }

  const platform = os.platform();

  printToInstall(toInstall, installData);

  if (!isa(SupportedPlatforms)(platform)) {
    throw (
      `Guided dependency installation is not available on platform ${platform}\n` +
      "Please install the above dependencies manually, or ensure they are on your PATH."
    );
  }

  const interactive = !!sys.writeOutputIsTTY?.() && (await queryInteractive());

  for (const item of toInstall) {
    if (interactive) await guidedInstall(platform, item, installData);
    else printInstallCommands(platform, item, installData);
  }

  const remaining = await requiredInstalls(installItems);

  if (remaining.length === 0) {
    print2("All packages successfully installed");
    return true;
  }
  return false;
};
