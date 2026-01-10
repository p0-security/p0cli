/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { getContactMessage } from "../../drivers/config";
import { print2 } from "../../drivers/stdio";
import { observedExit } from "../../opentelemetry/otel-helpers";
import {
  DENIED_STATUSES,
  DONE_STATUSES,
  ERROR_STATUSES,
  PermissionRequest,
  PluginRequest,
} from "../../types/request";
import { sys } from "typescript";

/**
 * process request status to determine the success of the operation
 * @param request
 * @returns
 */
export const decodeProvisionStatus = <P extends PluginRequest>(
  request: PermissionRequest<P>
) => {
  if (DENIED_STATUSES.includes(request.status as any)) {
    print2("Your access request was denied");
    sys.exit(1);
  } else if (ERROR_STATUSES.includes(request.status as any)) {
    const message =
      request.error?.message ??
      `Your access request encountered an unknown error. ${getContactMessage()}`;
    print2(message);
    observedExit(1, message);
  } else if (!DONE_STATUSES.includes(request.status as any)) {
    sys.exit(1);
  }
};
