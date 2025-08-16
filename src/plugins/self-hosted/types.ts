/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { PermissionSpec } from "../../types/request";
import { CliPermissionSpec } from "../../types/ssh";
import { CommonSshPermissionSpec } from "../ssh/types";

export type SelfHostedSshPermission = CommonSshPermissionSpec & {
  provider: "self-hosted";
  resource: {
    hostname: string;
    publicIp: string;
  };
};

export type SelfHostedSshGenerated = {
  linuxUserName: string;
  publicKey: string;
};

export type SelfHostedSshPermissionSpec = PermissionSpec<
  "ssh",
  SelfHostedSshPermission,
  SelfHostedSshGenerated
>;

export type SelfHostedSsh = CliPermissionSpec<
  SelfHostedSshPermissionSpec,
  undefined
>;

export type SelfHostedSshRequest = {
  type: "self-hosted";
  linuxUserName: string;
  id: string;
};
