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

type SshCommandArgs = { instance: string; command?: string };

/** Maximum amount of time to wait after access is approved to wait for access
 *  to be configured
 */
const GRANT_TIMEOUT_MILLIS = 60e3;

export const sshCommand = (yargs: yargs.Argv) =>
  yargs.command<SshCommandArgs>(
    "ssh <instance> [command]",
    "SSH into a virtual machine",
    (yargs) =>
      yargs
        .positional("instance", {
          type: "string",
          demandOption: true,
        })
        .option("command", {
          alias: "c",
          type: "string",
          describe: "Command to run on the remote machine",
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
  const response = await request(
    {
      ...pick(args, "$0", "_"),
      arguments: ["ssh", args.instance, "--provider", "aws"],
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
  await ssm(authn, { ...requestData, id, command: args.command });
};
