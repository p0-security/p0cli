/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { ensureInstall, InstallMetadata } from "../../common/install";

export const SupportedPlatforms = ["darwin"] as const;

const GcpSshItems = ["gcloud"] as const;
type GcpSshItem = (typeof GcpSshItems)[number];

const GcpSshInstall: Readonly<Record<GcpSshItem, InstallMetadata>> = {
  gcloud: {
    label: "GCloud CLI",
    commands: {
      darwin: [
        // See https://cloud.google.com/sdk/docs/install-sdk
        "architecture=$(arch)",
        'package=$([ $architecture = "arm64" ] && echo "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-darwin-arm.tar.gz" || "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-darwin-x86_64.tar.gz" )',
        "wget -O google-cloud-cli.tar.gz $package",
        "tar -xzf google-cloud-cli.tar.gz",
        "./google-cloud-sdk/install.sh",
        "rm -rf google-cloud-cli.tar.gz",
      ],
    },
  },
};

export const ensureGcpSshInstall = () =>
  ensureInstall(GcpSshItems, GcpSshInstall);
