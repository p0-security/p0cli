import yargs from "yargs";
import { authenticate } from "../drivers/firestore";

export const requestArgs = (yargs: yargs.Argv<{}>) =>
  yargs
    .parserConfiguration({ "unknown-options-as-args": true })
    .option("arguments", {
      array: true,
      string: true,
      default: [] as string[],
    });

const requestUrl = (tenant: string) =>
  `http://localhost:8088/o/${tenant}/command/`;

export const request = async (
  args: yargs.ArgumentsCamelCase<{ arguments: string[] }>
) => {
  const { userCredential, storedCredential } = await authenticate();
  const token = await userCredential.user.getIdToken();
  const response = await fetch(requestUrl(storedCredential.tenant), {
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
    } else if ("ok" in data && "message" in data && data.ok) {
      console.log(data.message);
    } else {
      console.error(data);
    }
  } catch (error: any) {
    console.error(await response.text());
  }
};
