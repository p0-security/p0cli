import { authenticate } from "../drivers/auth";
import { config } from "../drivers/env";
import { doc, guard } from "../drivers/firestore";
import { Authn } from "../types/identity";
import { Request } from "../types/request";
import { Unsubscribe, onSnapshot } from "firebase/firestore";
import * as path from "node:path";
import { sys } from "typescript";
import yargs from "yargs";

type OkCommandResponse = {
  ok: true;
  message: string;
  id: string;
  isPreexisting: string;
};
type ErrorCommandResponse = { error: string };
type CommandResponse = OkCommandResponse | ErrorCommandResponse;

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

const requestUrl = (tenant: string) => `${config.appUrl}/o/${tenant}/command/`;

const waitForRequest = async (
  tenantId: string,
  requestId: string,
  logMessage: boolean
) =>
  await new Promise<number>((resolve) => {
    if (logMessage)
      console.log("Will wait up to 5 minutes for this request to complete...");
    let unsubscribe: Unsubscribe | undefined;
    let cancel: NodeJS.Timeout | undefined;
    unsubscribe = onSnapshot<Request, object>(
      doc(`o/${tenantId}/permission-requests/${requestId}`),
      (snap) => {
        const data = snap.data();
        if (!data) return;
        const { status } = data;
        if (isCompletedStatus(status)) {
          if (cancel) clearTimeout(cancel);
          unsubscribe?.();
          const { message, code } = COMPLETED_REQUEST_STATUSES[status];
          if (code !== 0 || logMessage) console.log(message);
          resolve(code);
        }
      }
    );
    cancel = setTimeout(() => {
      unsubscribe?.();
      console.log("Your request did not complete within 5 minutes.");
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
): Promise<OkCommandResponse | undefined> => {
  const { userCredential, identity } = authn ?? (await authenticate());
  const token = await userCredential.user.getIdToken();
  const response = await fetch(requestUrl(identity.org.slug), {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      argv: ["request", ...args.arguments],
      scriptName: path.basename(args.$0),
    }),
  });
  const text = await response.text();
  const data = JSON.parse(text) as CommandResponse;
  if ("error" in data) {
    console.error(data.error);
    sys.exit(1);
    return undefined;
  } else if ("ok" in data && "message" in data && data.ok) {
    const logMessage =
      !options?.message ||
      options?.message === "all" ||
      (options?.message === "approval-required" && !data.isPreexisting);
    if (logMessage) console.error(data.message);
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
