/** Copyright © 2024-present P0 Security

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchCommand } from "../drivers/api";
import { authenticate } from "../drivers/auth";
import { doc, guard } from "../drivers/firestore";
import { print2 } from "../drivers/stdio";
import { Authn } from "../types/identity";
import { Request, RequestResponse } from "../types/request";
import { onSnapshot } from "firebase/firestore";
import { sys } from "typescript";
import yargs from "yargs";

const WAIT_TIMEOUT = 300e3;

const APPROVED = { message: "Your request was approved", code: 0 };
const DENIED = { message: "Your request was denied", code: 2 };
const ERRORED = { message: "Your request encountered an error", code: 1 };

const COMPLETED_REQUEST_STATUSES = {
  APPROVED,
  APPROVED_NOTIFIED: APPROVED,
  DONE: APPROVED,
  DONE_NOTIFIED: APPROVED,
  DENIED,
  ERRORED,
};
const isCompletedStatus = (
  status: any
): status is keyof typeof COMPLETED_REQUEST_STATUSES =>
  status in COMPLETED_REQUEST_STATUSES;

const requestArgs = <T>(yargs: yargs.Argv<T>) =>
  yargs
    .parserConfiguration({ "unknown-options-as-args": true })
    .help(false) // Turn off help in order to forward the --help command to the backend so P0 can provide the available requestable resources
    .option("wait", {
      alias: "w",
      boolean: true,
      default: false,
      describe: "Block until the command is completed",
    })
    .option("arguments", {
      array: true,
      string: true,
      default: [] as string[],
    });

export const requestCommand = (yargs: yargs.Argv) =>
  yargs.command<{ arguments: string[] }>(
    "request [arguments..]",
    "Manually request permissions on a resource",
    requestArgs,
    guard(request)
  );

const waitForRequest = async (
  tenantId: string,
  requestId: string,
  logMessage: boolean
) =>
  await new Promise<number>((resolve) => {
    if (logMessage)
      print2("Will wait up to 5 minutes for this request to complete...");
    let cancel: NodeJS.Timeout | undefined = undefined;
    const unsubscribe = onSnapshot<Request, object>(
      doc(`o/${tenantId}/permission-requests/${requestId}`),
      (snap) => {
        const data = snap.data();
        if (!data) return;
        const { status } = data;
        if (isCompletedStatus(status)) {
          if (cancel) clearTimeout(cancel);
          unsubscribe?.();
          const { message, code } = COMPLETED_REQUEST_STATUSES[status];
          if (code !== 0 || logMessage) print2(message);
          resolve(code);
        }
      }
    );
    cancel = setTimeout(() => {
      unsubscribe?.();
      print2("Your request did not complete within 5 minutes.");
      resolve(4);
    }, WAIT_TIMEOUT);
  });

export const request = async (
  args: yargs.ArgumentsCamelCase<{
    arguments: string[];
    wait?: boolean;
  }>,
  authn?: Authn,
  options?: {
    message?: "all" | "approval-required" | "none";
  }
): Promise<RequestResponse | undefined> => {
  const resolvedAuthn = authn ?? (await authenticate());
  const { userCredential } = resolvedAuthn;
  const data = await fetchCommand<RequestResponse>(resolvedAuthn, args, [
    "request",
    ...args.arguments,
  ]);

  if (data && "ok" in data && "message" in data && data.ok) {
    const logMessage =
      !options?.message ||
      options?.message === "all" ||
      (options?.message === "approval-required" &&
        !data.isPreexisting &&
        !data.isPersistent);
    if (logMessage) print2(data.message);
    const { id } = data;
    if (args.wait && id && userCredential.user.tenantId) {
      const code = await waitForRequest(
        userCredential.user.tenantId,
        id,
        logMessage
      );
      if (code) {
        sys.exit(code);
        return undefined;
      }
      return data;
    } else return undefined;
  } else {
    throw data;
  }
};
