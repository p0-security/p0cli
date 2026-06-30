/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { PermissionSpec } from "../../types/request";
import { CliPermissionSpec } from "../../types/ssh";
import { CommonSshPermissionSpec } from "../ssh/types";

export type AzureSshGenerated = {
  linuxUserName: string;
  directoryId: string;
};

export type AzureSshPermissionSpec = PermissionSpec<
  "ssh",
  AzureSshPermission,
  AzureSshGenerated
>;

export type AzureSsh = CliPermissionSpec<
  AzureSshPermissionSpec,
  AzureLocalData
>;

/** A jump host (a regular VM acting as an SSH bastion) that the target VM is
 * reached through via a plain SSH ProxyCommand (`ssh -W`). */
export type AzureSshJumpHost = {
  id: string;
  roleId: string;
  ip: string | undefined;
};

export type AzureSshPermission = CommonSshPermissionSpec & {
  provider: "azure";
  destination: string;
  parent: string | undefined;
  alias: string | undefined;
  group: string | undefined;
  sudo: boolean | undefined;
  region: string | undefined;
  publicKey: string | undefined;
  zone: string | undefined;
  // Exactly one of `bastionHost` (Azure Bastion tunnel) or `jumpHost` (SSH
  // ProxyCommand) is expected to be present for a connectable target.
  bastionHost: { id: string } | undefined;
  jumpHost: AzureSshJumpHost | undefined;
  accessRoleId: string;
  resource: {
    instanceName: string;
    instanceId: string;
    subscriptionId: string;
    subscriptionName: string;
    resourceGroupId: string;
    groupTag: { key: string; value: string } | undefined;
    region: string;
    networkInterface: {
      id: string;
      subnetId: string;
      privateIp: string | undefined;
    };
  };
};

export type AzureNodeSpec = {
  instanceId: string;
  sudo?: boolean;
};

export type AzureSshRequest = AzureNodeSpec &
  AzureLocalData & {
    type: "azure";
    // "localhost" for the Azure Bastion tunnel flow; the target VM's private IP
    // for the jump host flow.
    id: string;
    subscriptionId: string;
    directoryId: string;
    // Present for the Azure Bastion flow.
    bastionId: string | undefined;
    // Present for the jump host flow.
    jumpHost: AzureSshJumpHost | undefined;
    // The target VM's private IP (used as `id` for the jump host flow).
    privateIp: string | undefined;
  };

export type AzureLocalData = {
  linuxUserName: string;
};
