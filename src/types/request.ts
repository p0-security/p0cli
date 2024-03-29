/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
export const DONE_STATUSES = ["DONE", "DONE_NOTIFIED"] as const;
export const DENIED_STATUSES = ["DENIED", "DENIED_NOTIFIED"] as const;
export const ERROR_STATUSES = [
  "ERRORED",
  "ERRORED",
  "ERRORED_NOTIFIED",
] as const;

export type PluginRequest = {
  permission: object;
  generated?: object;
};

export type Request<P extends PluginRequest = { permission: object }> = {
  status: string;
  generatedRoles: {
    role: string;
  }[];
  generated: P["generated"];
  permission: P["permission"];
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
