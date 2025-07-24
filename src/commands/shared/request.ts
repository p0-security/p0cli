/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchCommand, fetchStreamingCommand } from "../../drivers/api";
import { authenticate } from "../../drivers/auth";
import { generateSpinUntil, print2, spinUntil } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import {
  PermissionRequest,
  PluginRequest,
  RequestResponse,
} from "../../types/request";
import { sys } from "typescript";
import yargs from "yargs";

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

const resolveCode = (
  permission: PermissionRequest<PluginRequest>,
  logMessage: boolean
) => {
  const { status } = permission;
  if (isCompletedStatus(status)) {
    const { message, code } = COMPLETED_REQUEST_STATUSES[status];
    const errorMessage = permission.error
      ? `${message}: ${permission.error.message}`
      : message;
    if (code !== 0 || logMessage) print2(errorMessage);
    return code;
  } else {
    print2("Your request did not complete within 5 minutes.");
    return 4;
  }
};

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
    const accessMessage = (message?: string) => {
      switch (message) {
        case "approval-required":
          return "Checking for access in P0";
        default:
          return "Requesting access";
      }
    };
    try {
      if (!args.wait) {
        const fetchCommandPromise = fetchCommand<RequestResponse<T>>(
          resolvedAuthn,
          args,
          [command, ...args.arguments]
        );
        const data =
          options?.message != "quiet"
            ? await spinUntil(
                accessMessage(options?.message),
                fetchCommandPromise
              )
            : await fetchCommandPromise;

        if (data && "ok" in data && "message" in data && data.ok) {
          const logMessage =
            !options?.message ||
            options?.message === "all" ||
            (options?.message === "approval-required" &&
              !data.isPreexisting &&
              !data.isPersistent);
          if (logMessage) print2(data.message);
          return data;
        } else {
          throw data;
        }
      } else {
        const fetchStreamingCommandPromise = fetchStreamingCommand<
          RequestResponse<T>
        >(resolvedAuthn, args, [command, ...args.arguments]);
        const fetchValue = async () => {
          const generatedValue = await fetchStreamingCommandPromise.next();
          if (generatedValue.done) {
            throw new Error("Could not get request id");
          }

          return generatedValue.value;
        };
        const data =
          options?.message != "quiet"
            ? await generateSpinUntil(
                accessMessage(options?.message),
                fetchStreamingCommandPromise
              )
            : await fetchValue();
        if (data && "ok" in data && "message" in data && data.ok) {
          const logMessage =
            !options?.message ||
            options?.message === "all" ||
            (options?.message === "approval-required" &&
              !data.isPreexisting &&
              !data.isPersistent);
          if (logMessage) print2(data.message);
          const finalData = await fetchValue();

          const code = resolveCode(
            finalData.request as PermissionRequest<PluginRequest>,
            logMessage
          );
          if (code) {
            sys.exit(code);
            return undefined;
          }
          return finalData;
        } else {
          throw data;
        }
      }
    } catch (error: any) {
      if (error instanceof Error && error.name === "TimeoutError") {
        print2("Your request did not complete within 5 minutes.");
        sys.exit(4);
      } else {
        print2(error);
        sys.exit(1);
      }
      return undefined;
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
    const response = await request("request")({ ...argv, wait: true }, authn, {
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
  } catch (error) {
    if (error === ACCESS_EXISTS_ERROR_MESSAGE) {
      print2(EXISTING_ACCESS_MESSAGE);
    } else {
      throw error;
    }
  }
};
