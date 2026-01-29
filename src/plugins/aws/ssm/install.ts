/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  AwsInstall,
  AwsItems,
  checkToolVersion,
  ensureInstall,
  InstallMetadata,
} from "../../../common/install";
import { print2 } from "../../../drivers/stdio";

const SsmItems = [...AwsItems, "session-manager-plugin"] as const;
type SsmItem = (typeof SsmItems)[number];

const SsmInstall: Readonly<Record<SsmItem, InstallMetadata>> = {
  ...AwsInstall,
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

/** Checks the AWS CLI version */
const checkAwsCliVersion = async (
  debug?: boolean
): Promise<string | undefined> => {
  const output = await checkToolVersion("AWS CLI", ["aws", "--version"], debug);
  if (!output) return undefined;

  // Parse: "aws-cli/2.15.23 Python/3.11.6 Darwin/25.2.0..."
  const match = output.match(/aws-cli\/(\d+\.\d+\.\d+)/);
  return match ? match[1] : undefined;
};

/** Checks the Session Manager Plugin version */
const checkSsmPluginVersion = async (
  debug?: boolean
): Promise<string | undefined> => {
  const output = await checkToolVersion(
    "Session Manager Plugin",
    ["session-manager-plugin", "--version"],
    debug
  );
  // Output is just the version number: "1.2.764.0"
  return output;
};

const validateSsmVersions = async (debug?: boolean): Promise<void> => {
  if (!debug) return;

  print2("[SSM Install Check] Checking AWS CLI installation...");
  const awsVersion = await checkAwsCliVersion(debug);
  if (awsVersion) {
    print2(`[SSM Install Check] AWS CLI version: ${awsVersion}`);
  } else {
    print2("[SSM Install Check] Warning: Could not determine AWS CLI version");
  }

  print2("[SSM Install Check] Checking Session Manager Plugin installation...");
  const ssmVersion = await checkSsmPluginVersion(debug);
  if (ssmVersion) {
    print2(`[SSM Install Check] Session Manager Plugin version: ${ssmVersion}`);
  } else {
    print2(
      "[SSM Install Check] Warning: Could not determine Session Manager Plugin version"
    );
  }

  print2("[SSM Install Check] All tools installed and validated");
};

/** Ensures that AWS CLI and SSM plugin are installed on the user environment
 *
 * If they are not, and the session is a TTY, prompt the user to auto-install. If
 * the user declines, or if not a TTY, the installation commands are printed to
 * stdout.
 *
 * If debug is enabled, also checks and logs the versions of installed tools.
 */
export const ensureSsmInstall = async (debug?: boolean): Promise<boolean> => {
  const installed = await ensureInstall(SsmItems, SsmInstall);

  if (installed && debug) {
    await validateSsmVersions(debug);
  }

  return installed;
};
