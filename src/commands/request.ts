import { authenticate } from "../drivers/auth";
import { config } from "../drivers/env";
import { doc, guard } from "../drivers/firestore";
import { Authn } from "../types/identity";
import { Request } from "../types/request";
import { Unsubscribe, onSnapshot } from "firebase/firestore";
import { sys } from "typescript";
import yargs from "yargs";

// TODO: Use structured exchange
const ID_PATTERN = /Created a new access <.*\/([^/|]+)\|request>/;
const WAIT_TIMEOUT = 300e3;

const COMPLETED_REQUEST_STATUSES = {
  APPROVED: { message: "Your request was approved", code: 0 },
  DENIED: { message: "Your request was denied", code: 2 },
  ERRORED: { message: "Your request encountered an error", code: 1 },
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

const waitForRequest = async (tenantId: string, requestId: string) =>
  await new Promise<number>((resolve) => {
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
          console.log(message);
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
  args: {
    arguments: string[];
    wait?: boolean;
  },
  authn?: Authn
): Promise<string | undefined> => {
  const { userCredential, identity } = authn ?? (await authenticate());
  const token = await userCredential.user.getIdToken();
  const response = await fetch(requestUrl(identity.org.slug), {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ argv: ["request", ...args.arguments] }),
  });
  const text = await response.text();
  const data = JSON.parse(text);
  if ("error" in data) {
    console.error(data.error);
    sys.exit(1);
    return undefined;
  } else if ("ok" in data && "message" in data && data.ok) {
    console.error(data.message);
    const idMatch = data.message.match(ID_PATTERN);
    if (!idMatch) throw "P0 application did not return a request ID";
    const [, requestId] = idMatch;
    if (args.wait && requestId && userCredential.user.tenantId) {
      const code = await waitForRequest(
        userCredential.user.tenantId,
        requestId
      );
      if (code) {
        sys.exit(code);
        return undefined;
      }
      return requestId;
    } else return undefined;
  } else {
    throw data;
  }
};
