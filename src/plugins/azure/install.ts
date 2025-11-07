/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  ensureInstall,
  HomebrewInstall,
  HomebrewItems,
  InstallMetadata,
} from "../../common/install";
import { getOperatingSystem } from "../../util";

const AzItems = [...HomebrewItems, "az"] as const;
type AzItem = (typeof AzItems)[number];

const AzInstall: Readonly<Record<AzItem, InstallMetadata>> = {
  ...HomebrewInstall,
  az: {
    label: "Azure command-line interface",
    commands: {
      darwin: ["brew update", "brew install azure-cli"],
    },
  },
};

export const ensureAzInstall = async () => {
  // ENG-6471: Add ensureInstall check to windows CLI
  const os = getOperatingSystem();
  if (os === "mac") {
    await ensureInstall(AzItems, AzInstall);
  }
  return true;
};
