/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { SshProvider } from "../../types/ssh";
import { importSshKey } from "./ssh-key";
import { GcpSshPermissionSpec, GcpSshRequest } from "./types";

export const gcpSshProvider: SshProvider<
  GcpSshPermissionSpec,
  { linuxUserName: string },
  GcpSshRequest
> = {
  requestToSsh: (request) => {
    return {
      id: request.permission.spec.instanceName,
      projectId: request.permission.spec.projectId,
      zone: request.permission.spec.zone,
      linuxUserName: request.cliLocalData.linuxUserName,
      type: "gcloud",
    };
  },
  toCliRequest: async (request, options) => ({
    ...request,
    cliLocalData: {
      linuxUserName: await importSshKey(
        request.permission.spec.publicKey,
        options
      ),
    },
  }),
};
