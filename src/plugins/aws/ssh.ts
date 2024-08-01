/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { CliRequest, Request } from "../../types/request";
import { AwsPermissionSpec, AwsSsh, AwsSshRequest } from "./types";

export const awsSshProvider = {
  requestToSsh: (request: AwsSsh): AwsSshRequest => {
    const { permission, generated } = request;
    const { instanceId, accountId, region } = permission.spec;
    const { idc, ssh, name } = generated;
    const { linuxUserName } = ssh;
    const common = { linuxUserName, accountId, region, id: instanceId };
    return !idc
      ? { ...common, role: name, type: "aws", access: "role" }
      : {
          ...common,
          idc,
          permissionSet: name,
          type: "aws",
          access: "idc",
        };
  },
  toCliRequest: async (
    request: Request<AwsPermissionSpec>
  ): Promise<Request<CliRequest>> => ({ ...request, cliLocalData: undefined }),
};
