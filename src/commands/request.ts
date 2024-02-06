import { authenticate } from "../drivers/auth";
import { config } from "../drivers/env";
import { doc, guard } from "../drivers/firestore";
import { Unsubscribe, onSnapshot } from "firebase/firestore";
import { sys } from "typescript";
import yargs from "yargs";

// TODO: Use structured exchange
const ID_PATTERN = /Created a new access request \(ID `([^`]+)`\)/;
const WAIT_TIMEOUT = 300e3;

const COMPLETED_REQUEST_STATUSES = {
  APPROVED: { message: "Your request was approved", code: 0 },
  DENIED: { message: "Your request was denied", code: 1 },
  ERRORED: { message: "Your request encountered an error", code: 2 },
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

const waitForRequest = async (tenantId: string, requestId: string) => {
  return new Promise<number>((resolve) => {
    console.log("Will wait up to 5 minutes for this request to complete...");
    let unsubscribe: Unsubscribe | undefined;
    let cancel: NodeJS.Timeout | undefined;
    unsubscribe = onSnapshot(
      doc(`o/${tenantId}/permission-requests/${requestId}`),
      (snap) => {
        const { status } = snap.data() as any;
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
};

const request = async (
  args: yargs.ArgumentsCamelCase<{ arguments: string[]; wait?: boolean }>
) => {
  const { userCredential, identity } = await authenticate();
  const token = await userCredential.user.getIdToken();
  const response = await fetch(requestUrl(identity.org.slug), {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ argv: ["request", ...args.arguments] }),
  });
  try {
    const data = await response.json();
    if ("error" in data) {
      console.error(data.error);
      sys.exit(2);
    } else if ("ok" in data && "message" in data && data.ok) {
      console.log(data.message);
      const idMatch = data.message.match(ID_PATTERN);
      if (args.wait && idMatch?.[1] && userCredential.user.tenantId) {
        const code = await waitForRequest(
          userCredential.user.tenantId,
          idMatch[1]
        );
        // Firestore holds the thread even if 'unsubscribe' is called
        sys.exit(code);
      }
    } else {
      console.error(data);
      sys.exit(2);
    }
  } catch (error: any) {
    console.error(await response.text());
    sys.exit(2);
  }
};
