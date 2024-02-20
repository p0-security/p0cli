import { authenticate } from "../drivers/auth";
import { doc, guard } from "../drivers/firestore";
import { ssm } from "../plugins/aws/ssm";
import { AwsSsh } from "../plugins/aws/types";
import { Authn } from "../types/identity";
import {
  DENIED_STATUSES,
  DONE_STATUSES,
  ERROR_STATUSES,
  Request,
} from "../types/request";
import { request } from "./request";
import { onSnapshot } from "firebase/firestore";
import { pick } from "lodash";
import yargs from "yargs";

/** Maximum amount of time to wait after access is approved to wait for access
 *  to be configured
 */
const GRANT_TIMEOUT_MILLIS = 60e3;

export const sshCommand = (yargs: yargs.Argv) =>
  yargs.command<{ instance: string }>(
    "ssh <instance>",
    "SSH into a virtual machine",
    (yargs) =>
      yargs.positional("instance", {
        type: "string",
        demandOption: true,
      }),
    guard(ssh)
  );

// TODO: Move this to a shared utility
/** Waits until P0 grants access for a request */
const waitForProvisioning = async <T extends object>(
  authn: Authn,
  requestId: string
) => {
  let cancel: NodeJS.Timeout | undefined = undefined;
  const result = await new Promise<Request<T>>((resolve, reject) => {
    let isResolved = false;
    const unsubscribe = onSnapshot<Request<T>, object>(
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
const ssh = async (args: yargs.ArgumentsCamelCase<{ instance: string }>) => {
  // Prefix is required because the backend uses it to determine that this is an AWS request
  const authn = await authenticate();
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
    console.error("Did not receive access ID from server");
    return;
  }
  const { id, isPreexisting } = response;
  if (!isPreexisting) console.error("Waiting for access to be provisioned");
  const requestData = await waitForProvisioning<AwsSsh>(authn, id);
  await ssm(authn, { ...requestData, id });
};