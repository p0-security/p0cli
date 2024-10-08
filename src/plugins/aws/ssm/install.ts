/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  AwsInstall,
  AwsItems,
  ensureInstall,
  InstallMetadata,
} from "../../../common/install";

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

/** Ensures that AWS CLI and SSM plugin are installed on the user environment
 *
 * If they are not, and the session is a TTY, prompt the user to auto-install. If
 * the user declines, or if not a TTY, the installation commands are printed to
 * stdout.
 */
export const ensureSsmInstall = () => ensureInstall(SsmItems, SsmInstall);
