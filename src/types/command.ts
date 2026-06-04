/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { PermissionRequest, PluginRequest } from "./request";

/** A single resource returned by the backend's resource lister (e.g. `ls`). */
export type ResourceListerItem = {
  key: string;
  value: string;
  group?: string;
  isPreexisting?: boolean;
};

/**
 * Canonical response shape for the `/command/` endpoint.
 *
 * Every successful variant may carry non-fatal `warnings` that should be
 * surfaced to the user without failing the command. The final variant is a
 * success that carries only warnings (no message, items, or request).
 */
export type CommandResult =
  | {
      ok: true;
      id: string;
      message: string;
      request: PermissionRequest<PluginRequest>;
      warnings?: string[];
    }
  | { error: string }
  | { ok: true; items: ResourceListerItem[]; warnings?: string[] }
  | { ok: true; message: string; warnings?: string[] }
  | { ok: true; warnings: string[] };
