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
} from "../../common/install";
import { print2 } from "../../drivers/stdio";

const EksItems = [...AwsItems, "kubectl"] as const;
type EksItem = (typeof EksItems)[number];

const GkeItems = ["gcloud", "kubectl"] as const;
type GkeItem = (typeof GkeItems)[number];

/**
 * Converts the current system architecture, as represented in TypeScript, to
 * the value used in the kubectl download URL, or throw an exception if the
 * current architecture is not one kubectl has an official build for.
 */
const kubectlDownloadArch = (): string => {
  const arch = process.arch;

  switch (arch) {
    case "x64": // macOS, Linux, and Windows
      return "amd64";
    case "arm64": // macOS and Linux only
      return arch;
    default:
      throw `Unsupported system architecture for kubectl: ${arch}. Please install kubectl manually, or check that it is available in your PATH.`;
  }
};

const kubectlInstallCommandsDarwin = (): Readonly<string[]> => {
  const arch = kubectlDownloadArch();

  // The download is the kubectl binary itself
  return [
    `curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/darwin/${arch}/kubectl"`,
    "chmod +x kubectl",
    "sudo mkdir -p /usr/local/bin",
    "sudo mv -i ./kubectl /usr/local/bin/kubectl",
    "sudo chown root: /usr/local/bin/kubectl",
  ];
};

const EksInstall: Readonly<Record<EksItem, InstallMetadata>> = {
  ...AwsInstall,
  kubectl: {
    label: "Kubernetes command-line tool",
    commands: {
      get darwin() {
        // Use a getter so that we only invoke kubectlInstallCommandsDarwin() if and when we
        // need to generate the installation commands so that we only check the architecture as
        // needed; if kubectl is already installed, doesn't really matter how it was installed
        // or whether it's an officially-supported architecture.
        return kubectlInstallCommandsDarwin();
      },
    },
  },
};

export const ensureEksInstall = async () =>
  await ensureInstall(EksItems, EksInstall);

const GkeInstall: Readonly<Record<GkeItem, InstallMetadata>> = {
  gcloud: {
    label: "Google Cloud SDK (gcloud CLI)",
    commands: {
      darwin: [
        'curl "https://sdk.cloud.google.com" | bash',
        "exec -l $SHELL",
        "gcloud init",
      ],
    },
  },
  kubectl: {
    label: "Kubernetes command-line tool",
    commands: {
      get darwin() {
        return kubectlInstallCommandsDarwin();
      },
    },
  },
};

export const ensureGkeInstall = async (debug?: boolean) => {
  if (debug) {
    print2("Checking for GKE dependencies: gcloud, kubectl");
  }
  return await ensureInstall(GkeItems, GkeInstall);
};
