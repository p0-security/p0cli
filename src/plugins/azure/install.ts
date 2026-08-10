/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  checkToolVersion,
  ensureInstall,
  HomebrewInstall,
  HomebrewItems,
  InstallMetadata,
} from "../../common/install";
import { print2 } from "../../drivers/stdio";
import { getOperatingSystem } from "../../util";
import {
  AZ_SSH_EXTENSION_ADD_COMMAND,
  azSshExtensionRemediation,
} from "./cert-error";

const os = getOperatingSystem();
const AzItems = os === "mac" ? [...HomebrewItems, "az"] : ["az"];

type AzItem = (typeof AzItems)[number];

export const AzInstall: Readonly<Record<AzItem, InstallMetadata>> = {
  ...(os === "mac" ? HomebrewInstall : {}),
  az: {
    label: "Azure command-line interface",
    commands: {
      // The `ssh` extension is required by `az ssh cert`; the Azure CLI is
      // always installed together with it, never alone
      darwin: [
        "brew update",
        "brew install azure-cli",
        AZ_SSH_EXTENSION_ADD_COMMAND,
      ],
    },
  },
};

/** The `ssh` extension (required by `az ssh cert`) is not a standalone
 * binary, so it is probed by running the Azure CLI instead of `which` */
const isAzSshExtensionInstalled = async (debug?: boolean) =>
  (await checkToolVersion(
    "the Azure CLI 'ssh' extension",
    ["az", "extension", "show", "--name", "ssh"],
    debug
  )) !== undefined;

export const ensureAzInstall = async (debug?: boolean) => {
  if (!(await ensureInstall(AzItems, AzInstall))) return false;

  if (await isAzSshExtensionInstalled(debug)) return true;

  print2(
    "The Azure CLI 'ssh' extension must be installed on your system to continue.\n\n" +
      azSshExtensionRemediation()
  );
  return false;
};
