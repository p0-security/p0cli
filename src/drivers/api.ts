import { config } from "../drivers/env";
import { Authn } from "../types/identity";
import { authenticate } from "./auth";
import * as path from "node:path";
import { sys } from "typescript";
import yargs from "yargs";

const commandUrl = (tenant: string) => `${config.appUrl}/o/${tenant}/command/`;

export const fetchCommand = async <T>(
  authn: Authn,
  args: yargs.ArgumentsCamelCase,
  argv: string[]
) => {
  const token = await authn.userCredential.user.getIdToken();
  const response = await fetch(commandUrl(authn.identity.org.slug), {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      argv,
      scriptName: path.basename(args.$0),
    }),
  });
  const text = await response.text();
  const data = JSON.parse(text);
  if ("error" in data) {
    console.error(data.error);
    sys.exit(1);
    return undefined;
  }
  return data as T;
};
