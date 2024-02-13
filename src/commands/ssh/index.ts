import { authenticate } from "../../drivers/auth";
import { doc, guard } from "../../drivers/firestore";
import { assumeRoleWithSaml } from "../../plugins/aws/assumeRole";
import { AwsCredentials } from "../../plugins/aws/types";
import { Authn } from "../../types/identity";
import {
  DENIED_STATUSES,
  DONE_STATUSES,
  ERROR_STATUSES,
  Request,
} from "../../types/request";
import { sleep } from "../../util";
import { initOktaSaml } from "../aws/role";
import { request } from "../request";
import { onSnapshot } from "firebase/firestore";
import { pick } from "lodash";
import { spawn } from "node-pty";
import yargs from "yargs";

const prefix = "arn:aws:ssm:us-west-2:391052057035:managed-instance/";

const GRANT_TIMEOUT_MILLIS = 60e3;

const INSTANCE_ARN_PATTERN =
  /^arn:aws:ssm:([^:]+):([^:]+):managed-instance\/([^:]+)$/;

const ssmDocumentArn = (requestId: string) =>
  `P0SshAsUser-${requestId}-nathan_brahms`;

type AwsSsh = {
  spec: {
    arn: string;
  };
  type: "session";
};

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

const waitForProvisioning = async (authn: Authn, requestId: string) => {
  let cancel: NodeJS.Timeout | undefined = undefined;
  const result = await new Promise<Request<AwsSsh>>((resolve, reject) => {
    let isResolved = false;
    const unsubscribe = onSnapshot<Request<AwsSsh>, object>(
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

const spawnSsm = async (args: {
  instance: string;
  region: string;
  requestId: string;
  credential: AwsCredentials;
}) =>
  new Promise((resolve, _reject) => {
    const cols = process.stdout.columns ?? 80;
    const rows = process.stdout.rows ?? 50;
    const child = spawn(
      "/usr/bin/env",
      [
        "aws",
        "ssm",
        "start-session",
        "--target",
        args.instance,
        "--document-name",
        ssmDocumentArn(args.requestId),
      ],
      {
        env: {
          ...process.env,
          ...args.credential,
          AWS_DEFAULT_REGION: args.region,
        },
        rows,
        cols,
      }
    );
    process.stdout.on("resize", () => {
      child.resize(process.stdout.columns, process.stdout.rows);
    });
    process.stdin.setRawMode(true);
    process.stdin.setEncoding("utf-8");
    const stdinListener = process.stdin.on("data", (d) =>
      child.write(d.toString("utf-8"))
    );
    process.stdin.resume();
    // TODO: separate stdout / stderr
    const outListener = child.onData((d) => process.stdout.write(d));
    const exitListener = child.onExit((code) => {
      process.stdin.setRawMode(false);
      process.stdin.resume();
      stdinListener.destroy();
      outListener.dispose();
      exitListener.dispose();
      console.error("SSH session terminated");
      resolve(code);
    });
  });

const ssm = async (authn: Authn, request: Request<AwsSsh> & { id: string }) => {
  const match = request.permission.spec.arn.match(INSTANCE_ARN_PATTERN);
  if (!match) throw "Did not receive a properly formatted instance identifier";
  const [, region, account, instance] = match;

  const { config, samlResponse } = await initOktaSaml(authn, account);
  const bastionCredential = await assumeRoleWithSaml({
    account: account!,
    role: request.generatedRoles[0]!.role,
    saml: {
      providerName: config.uidLocation.samlProviderName,
      response: samlResponse,
    },
  });

  await spawnSsm({
    instance: instance!,
    region: region!,
    requestId: request.id,
    credential: bastionCredential,
  });
};

const ssh = async (args: yargs.ArgumentsCamelCase<{ instance: string }>) => {
  const arn = `${prefix}${args.instance}`;
  const authn = await authenticate();
  const requestId = await request(
    {
      ...pick(args, "$0", "_"),
      arguments: ["ssh", "session", arn],
      wait: true,
    },
    authn
  );
  // Hard code for testing only
  // const requestId = "CJm7LNRbRtg1ca7da6k4";
  console.error("Waiting for access to be provisioned");
  if (!requestId) {
    console.error("Did not receive access ID from server");
    return;
  }
  const requestData = await waitForProvisioning(authn, requestId);
  // console.log(requestData);
  await ssm(authn, { ...requestData, id: requestId });
};
