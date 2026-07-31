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
import { exec, getOperatingSystem, osSafeCommand } from "../../util";
import {
  AZ_SSH_EXTENSION_ADD_COMMAND,
  azSshExtensionPipHint,
} from "./cert-error";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

const os = getOperatingSystem();

/** The default directory the Azure CLI installs the `ssh` extension into.
 * The Azure CLI discovers extensions by scanning this directory, so its
 * presence is equivalent to `az extension show --name ssh` succeeding —
 * unless a custom directory was set with `az config`, in which case this
 * misses and we fall back to asking the Azure CLI. */
const azSshExtensionDir = () => {
  const configDir =
    process.env.AZURE_CONFIG_DIR || path.join(homedir(), ".azure");
  const extensionDir =
    process.env.AZURE_EXTENSION_DIR || path.join(configDir, "cliextensions");
  return path.join(extensionDir, "ssh");
};

/** Whether the Azure CLI's `ssh` extension (required by `az ssh cert`) is
 * installed. The extension is not part of the base Azure CLI install. */
const isAzSshExtensionInstalled = async () => {
  // Fast path: this check runs on every connection, and spawning the Azure
  // CLI costs ~1s of Python startup, so avoid it in the steady state
  if (existsSync(azSshExtensionDir())) return true;

  try {
    const { command, args } = osSafeCommand("az", [
      "extension",
      "show",
      "--name",
      "ssh",
    ]);
    const { code } = await exec(command, args);
    return code === 0;
  } catch {
    // Spawn failure, e.g. `az` itself is missing; the `az` item is then
    // listed for installation ahead of the extension
    return false;
  }
};

// The extension pre-flight check is limited to macOS, the only platform with
// guided installation (as for every other integration). Elsewhere the Azure
// CLI's own dynamic install handles a missing extension on first use of
// `az ssh cert`, and cert-error.ts classifies the failure if that breaks.
const AzItems =
  os === "mac" ? [...HomebrewItems, "az", "az-ssh-extension"] : ["az"];

type AzItem = (typeof AzItems)[number];

export const AzInstall: Readonly<Record<AzItem, InstallMetadata>> = {
  ...(os === "mac" ? HomebrewInstall : {}),
  az: {
    label: "Azure command-line interface",
    commands: {
      darwin: ["brew update", "brew install azure-cli"],
    },
  },
  "az-ssh-extension": {
    label: "the Azure CLI 'ssh' extension",
    commands: {
      darwin: [AZ_SSH_EXTENSION_ADD_COMMAND],
    },
    isInstalled: isAzSshExtensionInstalled,
    failureHint: azSshExtensionPipHint(),
  },
};

export const ensureAzInstall = async () =>
  await ensureInstall(AzItems, AzInstall);
