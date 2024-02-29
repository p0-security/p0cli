/** Copyright © 2024-present P0 Security

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authenticate } from "../drivers/auth";
import { doc, guard } from "../drivers/firestore";
import { print2 } from "../drivers/stdio";
import { ssm } from "../plugins/aws/ssm";
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

export type SshCommandArgs = {
  destination: string;
  command?: string;
  L?: string; // port forwarding option
  arguments: string[];
  sudo?: boolean;
};

// Matches strings with the pattern "digits:digits" (e.g. 1234:5678)
const LOCAL_PORT_FORWARD_PATTERN = /^\d+:\d+$/;

/** Maximum amount of time to wait after access is approved to wait for access
 *  to be configured
 */
const GRANT_TIMEOUT_MILLIS = 60e3;

export const sshCommand = (yargs: yargs.Argv) =>
  yargs.command<SshCommandArgs>(
    "ssh <destination> [command [arguments..]]",
    "SSH into a virtual machine",
    (yargs) =>
      yargs
        .positional("destination", {
          type: "string",
          demandOption: true,
        })
        .option("sudo", {
          type: "boolean",
          describe: "Add user to sudoers file",
        })
        .positional("command", {
          type: "string",
          describe: "Pass command to the shell",
        })
        .positional("arguments", {
          describe: "Command arguments",
          array: true,
          string: true,
          default: [] as string[],
        })
        .check((argv: yargs.ArgumentsCamelCase<SshCommandArgs>) => {
          if (argv.L == null) return true;

          return (
            argv.L.match(LOCAL_PORT_FORWARD_PATTERN) ||
            "Local port forward should be in the format `local_port:remote_port`"
          );
        })
        .option("L", {
          type: "string",
          describe:
            // the order of the sockets in the address matches the ssh man page
            "Forward a local port to the remote host; `local_socket:remote_socket`",
        }),
    guard(ssh)
  );

const validateSshInstall = async (authn: Authn) => {
  const configDoc = await getDoc<SshConfig, object>(
    doc(`o/${authn.identity.org.tenantId}/integrations/ssh`)
  );
  const items = configDoc
    .data()
    ?.workflows?.items.filter(
      (i) => i.state === "installed" && i.type === "aws"
    );
  if (!items?.length) {
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

/** Connect to an SSH backend
 *
 * Implicitly gains access to the SSH resource if required.
 *
 * Supported SSH mechanisms:
 * - AWS EC2 via SSM with Okta SAML
 */
const ssh = async (args: yargs.ArgumentsCamelCase<SshCommandArgs>) => {
  // Prefix is required because the backend uses it to determine that this is an AWS request
  const authn = await authenticate();
  await validateSshInstall(authn);
  const requestArgs = ["ssh", args.destination, "--provider", "aws"];
  if (args.sudo || args.command === "sudo") requestArgs.push("--sudo");
  const response = await request(
    {
      ...pick(args, "$0", "_"),
      arguments: requestArgs,
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

  const requestData = await waitForProvisioning<AwsSsh>(authn, id);
  const requestWithId = { ...requestData, id };

  await ssm(authn, requestWithId, args);
};
