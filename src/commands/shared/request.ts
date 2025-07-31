/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { waitForProvisioning } from ".";
import { fetchCommand } from "../../drivers/api";
import { authenticate } from "../../drivers/auth";
import { doc } from "../../drivers/firestore";
import { print2, spinUntil } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import {
  PluginRequest,
  PermissionRequest,
  RequestResponse,
} from "../../types/request";
import { onSnapshot } from "firebase/firestore";
import { sys } from "typescript";
import yargs from "yargs";

const WAIT_TIMEOUT = 300e3;

export const PROVISIONING_ACCESS_MESSAGE =
  "Waiting for access to be provisioned";
export const EXISTING_ACCESS_MESSAGE = "Existing access found.";
export const ACCESS_EXISTS_ERROR_MESSAGE =
  "This principal already has this access";

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

export const requestArgs = <T>(yargs: yargs.Argv<T>) =>
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

const waitForRequest = async (
  tenantId: string,
  requestId: string,
  logMessage: boolean
) =>
  await new Promise<number>((resolve) => {
    if (logMessage)
      print2("Will wait up to 5 minutes for this request to complete...");
    let cancel: NodeJS.Timeout | undefined = undefined;
    const unsubscribe = onSnapshot<PermissionRequest<PluginRequest>, object>(
      doc(`o/${tenantId}/permission-requests/${requestId}`),
      (snap) => {
        const data = snap.data();
        if (!data) return;
        const { status } = data;
        if (isCompletedStatus(status)) {
          if (cancel) clearTimeout(cancel);
          unsubscribe?.();
          const { message, code } = COMPLETED_REQUEST_STATUSES[status];
          const errorMessage = data.error
            ? `${message}: ${data.error.message}`
            : message;
          if (code !== 0 || logMessage) print2(errorMessage);
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

export const request =
  (command: "grant" | "request") =>
  async <T>(
    args: yargs.ArgumentsCamelCase<{
      arguments: string[];
      wait?: boolean;
    }>,
    authn?: Authn,
    options?: {
      accessMessage?: string;
      message?: "all" | "approval-required" | "none" | "quiet";
    }
  ): Promise<RequestResponse<T> | undefined> => {
    const resolvedAuthn = authn ?? (await authenticate());
    const { identity } = resolvedAuthn;
    const { tenantId } = identity.org;
    const accessMessage = (message?: string) => {
      switch (message) {
        case "approval-required":
          return "Checking for access in P0";
        default:
          return "Requesting access";
      }
    };

    const fetchCommandPromise = fetchCommand<RequestResponse<T>>(
      resolvedAuthn,
      args,
      [command, ...args.arguments]
    );

    const data =
      options?.message != "quiet"
        ? await spinUntil(accessMessage(options?.message), fetchCommandPromise)
        : await fetchCommandPromise;

    if (data && "ok" in data && "message" in data && data.ok) {
      const logMessage =
        !options?.message ||
        options?.message === "all" ||
        (options?.message === "approval-required" &&
          !data.isPreexisting &&
          !data.isPersistent);
      if (logMessage) print2(data.message);
      const { id } = data;
      if (args.wait && id && tenantId) {
        const code = await waitForRequest(tenantId, id, logMessage);
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

export const provisionRequest = async (
  argv: yargs.ArgumentsCamelCase<{
    arguments: string[];
    wait?: boolean;
  }>,
  authn: Authn
) => {
  try {
    const response = await request("request")(argv, authn, {
      message: "approval-required",
    });

    if (!response) {
      print2("Did not receive access ID from server");
      return;
    }

    const { id, isPreexisting } = response;

    print2(
      !isPreexisting ? PROVISIONING_ACCESS_MESSAGE : EXISTING_ACCESS_MESSAGE
    );
    await waitForProvisioning<PluginRequest>(authn, id);
  } catch (error) {
    if (error === ACCESS_EXISTS_ERROR_MESSAGE) {
      print2(EXISTING_ACCESS_MESSAGE);
    } else {
      throw error;
    }
  }
};
