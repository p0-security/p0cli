import { PermissionSpec } from "../../types/request";
import { CliPermissionSpec } from "../../types/ssh";
import { CommonSshPermissionSpec } from "../ssh/types";

/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
export type AzureSshPermission = {
  spec: CommonSshPermissionSpec & {
    type: "azure";
    subscriptionId: string;
    subscriptionName: string;
    resourceGroupId: string;
    bastionHostId: string;
    instanceId: string;
    accessRoleId: string;
    publicKey: string;
    name: string;
    region: string;
    networkInterfaceIds: string[];
    tags: Record<string, string>;
    sudo?: boolean;
  };
  type: "session";
};

export type AzureSshGenerated = {
  bastionHostRoleAssignmentId: string;
  networkCardRoleAssignmentId: string;
  virtualMachineRoleAssignmentId: string;
};

export type AzureSshLocalData = undefined;

export type AzureSshRequest = {
  linuxUserName: string;
  bastionHostId: string;
  id: string;
  type: "azure";
};

export type AzureSshPermissionSpec = PermissionSpec<
  "ssh",
  AzureSshPermission,
  AzureSshGenerated
>;
export type AzureSsh = CliPermissionSpec<
  AzureSshPermissionSpec,
  AzureSshLocalData
>;

export type ScopeInfo = {
  resourceId: string;
  providerType: string;
  resourceType: string;
  resourceGroupId: string;
  subscriptionId: string;
};
