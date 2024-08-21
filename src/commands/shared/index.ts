/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { doc } from "../../drivers/firestore";
import { Authn } from "../../types/identity";
import {
  DENIED_STATUSES,
  DONE_STATUSES,
  ERROR_STATUSES,
  PluginRequest,
  Request,
} from "../../types/request";
import { onSnapshot } from "firebase/firestore";

/** Maximum amount of time to wait after access is approved to wait for access
 *  to be configured
 */
const GRANT_TIMEOUT_MILLIS = 60e3;

/** Waits until P0 grants access for a request */
export const waitForProvisioning = async <P extends PluginRequest>(
  authn: Authn,
  requestId: string
) => {
  let cancel: NodeJS.Timeout | undefined = undefined;
  const result = await new Promise<Request<P>>((resolve, reject) => {
    let isResolved = false;
    const unsubscribe = onSnapshot<Request<P>, object>(
      doc(`o/${authn.identity.org.tenantId}/permission-requests/${requestId}`),
      (snap) => {
        const data = snap.data();
        if (!data) return;
        if (DONE_STATUSES.includes(data.status as any)) {
          resolve(data);
        } else if (DENIED_STATUSES.includes(data.status as any)) {
          reject("Your access request was denied");
        } else if (ERROR_STATUSES.includes(data.status as any)) {
          reject(
            "Your access request encountered an error (see Slack for details)"
          );
        } else {
          return;
        }
        isResolved = true;
        unsubscribe();
      }
    );
    // Skip timeout in test; it holds a ref longer than the test lasts
    if (process.env.NODE_ENV === "test") return;
    cancel = setTimeout(() => {
      if (!isResolved) {
        unsubscribe();
        reject("Timeout awaiting access grant. Please try again.");
      }
    }, GRANT_TIMEOUT_MILLIS);
  });
  clearTimeout(cancel);
  return result;
};
