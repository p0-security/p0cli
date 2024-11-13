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

// TODO: Placeholder; confirm this is correct
export type AzureSsh = CliPermissionSpec<
  AzureSshPermissionSpec,
  { linuxUserName: string }
>;

export type AzureSshPermission = CommonSshPermissionSpec & {
  provider: "azure";
  destination: string;
  parent: string | undefined;
  group: string | undefined;
  resource: {
    instanceName: string;
    instanceId: string;
    subscriptionId: string;
    subscriptionName: string;
    resourceGroupId: string;
    region: string;
    networkInterfaceIds: string[];
  };
};

// TODO: Placeholder; probably wrong
export type AzureNodeSpec = {
  type: "azure";
  instanceId: string;
  sudo?: boolean;
};

// TODO: Placeholder; probably wrong
export type AzureSshRequest = AzureNodeSpec & {
  id: string;
  linuxUserName: string;
};
