import yargs from "yargs";
import open from "open";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { sys } from "typescript";
import { sleep } from "../util";
import { authenticate } from "../drivers/firestore";

// cf. https://www.oauth.com/oauth2-servers/device-flow/

// TODO: Generate at install time
const CLIENT_ID = "p0cli_6e522d700f09981af7814c8b98b021f9";

const GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

interface CodeData {
  device_code: string;
  user_code: string;
  verification_uri: string;
  interval: number;
  expires_in: number;
}

type TokenErrorResponse = {
  error:
    | "missing parameter"
    | "not found"
    | "bad grant type"
    | "slow_down"
    | "authorization_pending"
    | "access_denied"
    | "expired_token";
};

const tokenUrl = (tenantSlug: string) =>
  `http://localhost:8081/o/${tenantSlug}/token`;

const oauthDFGetCode = async (tenantSlug: string) => {
  const params = new URLSearchParams();
  params.append("client_id", CLIENT_ID);
  const response = await fetch(tokenUrl(tenantSlug), {
    method: "POST",
    body: params,
  });
  if (response.status !== 200) {
    throw `could not start login: ${await response.text()}`;
  }
  return (await response.json()) as CodeData;
};

const oauthDFGetToken = async (
  tenantSlug: string,
  codeData: CodeData
): Promise<object> => {
  const params = new URLSearchParams();
  params.append("client_id", CLIENT_ID);
  params.append("device_code", codeData.device_code);
  params.append("grant_type", GRANT_TYPE);
  const response = await fetch(tokenUrl(tenantSlug), {
    method: "POST",
    body: params,
  });
  switch (response.status) {
    case 200:
      const data = await response.json();
      return data as object;
    case 400:
      const error = ((await response.json()) as TokenErrorResponse).error;
      switch (error) {
        case "slow_down":
        case "authorization_pending":
          await sleep(codeData.interval);
          return oauthDFGetToken(tenantSlug, codeData);
        default:
          throw error;
      }
    default:
      throw await response.text();
  }
};

export const login = async (
  args: yargs.ArgumentsCamelCase<{ tenant: string }>
) => {
  const codeData = await oauthDFGetCode(args.tenant);
  const url = codeData.verification_uri;

  console.log(`Opening a web browser at the following location:

    ${url}

  When prompted, please enter the following code:

    ${codeData.user_code}
  `);

  // No need to await the browser process
  open(url);

  console.log(`Waiting for authorization ...`);

  const tokenData = await oauthDFGetToken(args.tenant, codeData);

  console.log(`Authorized.`);

  console.log(`Saving authorization to ~/.p0cli/identity.json.`);

  const dir = path.join(os.homedir(), ".p0cli");
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir);
  }
  fs.writeFileSync(path.join(dir, "identity.json"), JSON.stringify(tokenData), {
    mode: "600",
  });

  // validate auth
  await authenticate();

  console.log(`You are now logged in, and can use p0cli.`);

  sys.exit(0);
};

export const loginArgs = (yargs: yargs.Argv<{}>) =>
  yargs.positional("tenant", {
    demandOption: true,
    type: "string",
    describe: "Your P0 tenant ID",
  });
