/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  AwsSsh,
  AwsSshPermissionSpec,
  AwsSshRequest,
} from "../plugins/aws/types";
import {
  GcpSsh,
  GcpSshPermissionSpec,
  GcpSshRequest,
} from "../plugins/google/types";
import { Request } from "./request";

export type CliSshRequest = AwsSsh | GcpSsh;
export type PluginSshRequest = AwsSshPermissionSpec | GcpSshPermissionSpec;

export type CliPermissionSpec<
  P extends PluginSshRequest,
  C extends object | undefined,
> = P & {
  cliLocalData: C;
};

// The prefix of installed SSH accounts in P0 is the provider name
export const SupportedSshProviders = ["aws", "gcloud"] as const;
export type SupportedSshProvider = (typeof SupportedSshProviders)[number];

export type SshProvider<
  PR extends PluginSshRequest = PluginSshRequest,
  O extends object | undefined = undefined,
  SR extends SshRequest = SshRequest,
> = {
  requestToSsh: (request: CliPermissionSpec<PR, O>) => SR;
  toCliRequest: (
    request: Request<PR>,
    options?: { debug?: boolean }
  ) => Promise<Request<CliSshRequest>>;
};

export type SshRequest = AwsSshRequest | GcpSshRequest;
