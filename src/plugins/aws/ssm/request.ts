/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { request } from "../../../commands/request";
import { BaseSshCommandArgs } from "../../../commands/types";
import { authenticate } from "../../../drivers/auth";
import { doc } from "../../../drivers/firestore";
import { print2 } from "../../../drivers/stdio";
import { Authn } from "../../../types/identity";
import {
  DENIED_STATUSES,
  DONE_STATUSES,
  ERROR_STATUSES,
  PluginRequest,
  Request,
} from "../../../types/request";
import { SshConfig } from "../../ssh/types";
import { AwsSsh } from "../types";
import { getDoc, onSnapshot } from "firebase/firestore";
import { pick } from "lodash";
import yargs from "yargs";

/** Maximum amount of time to wait after access is approved to wait for access
 *  to be configured
 */
const GRANT_TIMEOUT_MILLIS = 60e3;

const validateSshInstall = async (authn: Authn) => {
  const configDoc = await getDoc<SshConfig, object>(
    doc(`o/${authn.identity.org.tenantId}/integrations/ssh`)
  );
  const configItems = configDoc.data()?.["iam-write"];

  const items = Object.entries(configItems ?? {}).filter(
    ([key, value]) => value.state == "installed" && key.startsWith("aws")
  );
  if (items.length === 0) {
    throw "This organization is not configured for SSH access via the P0 CLI";
  }
};

// TODO: Move this to a shared utility
/** Waits until P0 grants access for a request */
const waitForProvisioning = async <P extends PluginRequest>(
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
        reject("Timeout awaiting SSH access grant");
      }
    }, GRANT_TIMEOUT_MILLIS);
  });
  clearTimeout(cancel);
  return result;
};

export const sshRequest = async (
  args: yargs.ArgumentsCamelCase<BaseSshCommandArgs>
) => {
  // Prefix is required because the backend uses it to determine that this is an AWS request
  const authn = await authenticate();
  await validateSshInstall(authn);
  const response = await request<AwsSsh>(
    {
      ...pick(args, "$0", "_"),
      arguments: [
        "ssh",
        "session",
        args.destination,
        "--provider",
        "aws",
        ...(args.sudo || args.command === "sudo" ? ["--sudo"] : []),
        ...(args.reason ? ["--reason", args.reason] : []),
        ...(args.account ? ["--account", args.account] : []),
      ],
      wait: true,
    },
    authn,
    { message: "approval-required" }
  );
  if (!response) {
    print2("Did not receive access ID from server");
    return;
  }
  const { id, isPreexisting, event } = response;
  if (!isPreexisting) print2("Waiting for access to be provisioned");

  /**
   * TODO TECH-DEBT ENG-1813:
   * We use the id and waitForProvisioning to find the permission request document which has
   * critical data, such as the document name and generated role, that we need to build up a
   * viable SSM request.
   *
   * Replacing the permission with event.permission is necessary when trying to connect to an
   * instance which has been granted approval through it's group. The event.permission object
   * will contain details about the specific instance we are trying to connect to such as the
   * instance id. Without an instance id, which an SSH group permission request document does
   * not contain we cannot construct a valid SSM command.
   */
  const requestData = await waitForProvisioning<AwsSsh>(authn, id);
  const requestWithId = { ...requestData, id, permission: event.permission };

  return { authn, requestWithId };
};
