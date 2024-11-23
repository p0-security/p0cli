/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { PermissionSpec } from "../../types/request";
import { CliPermissionSpec } from "../../types/ssh";
import { CommonSshPermissionSpec } from "../ssh/types";

export type AzureSshPermissionSpec = PermissionSpec<"ssh", AzureSshPermission>;

export type AzureSsh = CliPermissionSpec<
  AzureSshPermissionSpec,
  AzureLocalData
>;

export type AzureSshPermission = CommonSshPermissionSpec & {
  provider: "azure";
  destination: string;
  parent: string | undefined;
  group: string | undefined;
  bastionHostId: string;
  principal: string;
  resource: {
    instanceId: string;
    instanceName: string;
    subscriptionName: string;
    resourceGroupId: string;
    subscriptionId: string;
    region: string;
    networkInterfaceIds: string[];
  };
};

export type AzureNodeSpec = {
  instanceId: string;
  sudo?: boolean;
};

export type AzureBastionSpec = {
  bastionId: string;
};

export type AzureSshRequest = AzureNodeSpec &
  AzureBastionSpec &
  AzureLocalData & {
    type: "azure";
    id: "localhost"; // Azure SSH always connects to the local tunnel
    subscriptionId: string;
  };

export type AzureLocalData = {
  linuxUserName: string;
};
