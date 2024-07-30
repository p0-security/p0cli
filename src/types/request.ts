/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { AwsPermissionSpec, AwsSsh } from "../plugins/aws/types";
import { GcpPermissionSpec, GcpSsh } from "../plugins/google/types";

export const DONE_STATUSES = ["DONE", "DONE_NOTIFIED"] as const;
export const DENIED_STATUSES = ["DENIED", "DENIED_NOTIFIED"] as const;
export const ERROR_STATUSES = [
  "ERRORED",
  "ERRORED",
  "ERRORED_NOTIFIED",
] as const;

export type CliRequest = AwsSsh | GcpSsh;
export type PluginRequest = AwsPermissionSpec | GcpPermissionSpec;

export type CliPermissionSpec<
  P extends PluginRequest,
  C extends object | undefined = undefined,
> = P & {
  cliLocalData: C;
};

export type PermissionSpec<
  K extends string,
  P extends { type: string },
  G extends object | undefined = undefined,
> = {
  type: K;
  permission: P;
  generated: G;
};

export type Request<P extends PluginRequest> = P & {
  status: string;
  principal: string;
};

export type RequestResponse<T> = {
  ok: true;
  message: string;
  id: string;
  event: T;
  isPreexisting: boolean;
  isPersistent: boolean;
};
