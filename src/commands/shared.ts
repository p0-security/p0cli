/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { doc } from "../drivers/firestore";
import { print2 } from "../drivers/stdio";
import { AwsSsh } from "../plugins/aws/types";
import { SshConfig } from "../plugins/ssh/types";
import { Authn } from "../types/identity";
import {
  DENIED_STATUSES,
  DONE_STATUSES,
  ERROR_STATUSES,
  PluginRequest,
  Request,
} from "../types/request";
import { request } from "./request";
import { getDoc, onSnapshot } from "firebase/firestore";
import { pick } from "lodash";
import yargs from "yargs";

/** Maximum amount of time to wait after access is approved to wait for access
 *  to be configured
 */
const GRANT_TIMEOUT_MILLIS = 60e3;

export type ExerciseGrantResponse = {
  documentName: string;
  linuxUserName: string;
  ok: true;
  role: string;
  privateKey?: string;
  instance: {
    arn: string;
    accountId: string;
    region: string;
    id: string;
    name?: string;
  };
};

export type BaseSshCommandArgs = {
  sudo?: boolean;
  reason?: string;
  account?: string;
};

export type ScpCommandArgs = BaseSshCommandArgs & {
  source: string;
  destination: string;
  recursive?: boolean;
};

export type SshCommandArgs = BaseSshCommandArgs & {
  sudo?: boolean;
  destination: string;
  L?: string; // Port forwarding option
  N?: boolean; // No remote command
  arguments: string[];
  command?: string;
};

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

export const provisionRequest = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<BaseSshCommandArgs>,
  destination: string
) => {
  await validateSshInstall(authn);

  const response = await request<AwsSsh>(
    {
      ...pick(args, "$0", "_"),
      arguments: [
        "ssh",
        "session",
        destination,
        // Prefix is required because the backend uses it to determine that this is an AWS request
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
  const { id, isPreexisting } = response;
  if (!isPreexisting) print2("Waiting for access to be provisioned");

  await waitForProvisioning<AwsSsh>(authn, id);

  return id;
};
