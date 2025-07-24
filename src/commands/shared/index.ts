/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import {
  DENIED_STATUSES,
  DONE_STATUSES,
  ERROR_STATUSES,
  PermissionRequest,
  PluginRequest,
} from "../../types/request";

/** Waits until P0 grants access for a request */
export const waitForProvisioning = async <P extends PluginRequest>(
  request: PermissionRequest<P>
) => {
  try {
    if (DONE_STATUSES.includes(request.status as any)) {
      print2("Access has been granted");
      return true;
    } else if (DENIED_STATUSES.includes(request.status as any)) {
      print2("Your access request was denied");
    } else if (ERROR_STATUSES.includes(request.status as any)) {
      print2(
        "Your access request encountered an error (see Slack for details)"
      );
    }
    return false;
  } catch (error: any) {
    if (error instanceof Error && error.name === "TimeoutError") {
      print2("Your request did not complete within 5 minutes.");
      throw new Error("Timeout waiting for access to be granted");
    } else {
      print2(error);
      throw error;
    }
  }
};
