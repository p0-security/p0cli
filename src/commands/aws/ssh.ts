/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import crypto from "crypto";
import yargs from "yargs";
import { assumeRoleWithIdc } from "../../plugins/aws/idc";
import { getAwsConfig } from "../../plugins/aws/config";
import { AwsCredentials } from "../../plugins/aws/types";

type UploadKeyCommandArgs = {
  account: string | undefined;
  debug: boolean | undefined;
  instanceId: string;
  publicKey: string;
};

export const ssh = (
  yargs: yargs.Argv<{ account: string | undefined }>,
  authn: Authn
) =>
  yargs.command("ssh", "AWS SSH utilities", (yargs) =>
    yargs.command(
      "upload-key <instance-id>",
      "Upload a public key to an EC2 instance via Lambda",
      (y: yargs.Argv<{ account: string | undefined }>) =>
        y
          .positional("instance-id", {
            type: "string",
            demandOption: true,
            describe: "The EC2 instance ID",
          })
          .option("public-key", {
            type: "string",
            demandOption: true,
            describe: "The SSH public key to upload",
          }),
      (argv) =>
        uploadKeyAction(
          argv as unknown as yargs.ArgumentsCamelCase<UploadKeyCommandArgs>,
          authn
        )
    )
  );

const uploadKeyAction = async (
  argv: yargs.ArgumentsCamelCase<UploadKeyCommandArgs>,
  authn: Authn
) => {
  const { instanceId, publicKey, account, debug } = argv;
  print2(`Uploading public key to instance ${instanceId}...`);

  // Get credentials - try IDC first, fall back to env vars
  const credentials = await getCredentials(authn, account, debug);

  const apiGatewayUrl =
    "https://zfg44axcs9.execute-api.us-east-2.amazonaws.com/dev/upload-key";
  const region = "us-east-2";
  const body = JSON.stringify({ action: "upload", instanceId, publicKey });
  

  if (debug) {
    print2(`URL: ${apiGatewayUrl}`);
    print2(`Region: ${region}`);
    print2(`Body: ${body}`);
  }

  // Sign the request
  const signedHeaders = signRequest({
    method: "POST",
    url: apiGatewayUrl,
    body,
    region,
    service: "execute-api",
    credentials,
  });

  const response = await fetch(apiGatewayUrl, {
    method: "POST",
    headers: {
      ...signedHeaders,
      "Content-Type": "application/json",
    },
    body,
  });

  const responseText = await response.text();

  if (debug) {
    print2(`Response: ${response.status} ${responseText}`);
  }

  if (!response.ok) {
    throw new Error(`Failed: ${response.status} ${responseText}`);
  }

  print2(`Success!`);
};

// ============ Credentials ============

type SigningCredentials = {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
};

async function getCredentials(
  authn: Authn,
  account: string | undefined,
  debug: boolean | undefined
): Promise<SigningCredentials> {
  // Try P0 IDC first
  try {
    const { config } = await getAwsConfig(authn, account, debug);
    if (config.login?.type === "idc") {
      const { login } = config;
      if (debug) print2(`Using P0 IDC credentials (account: ${config.id})`);

      const creds: AwsCredentials = await assumeRoleWithIdc({
        accountId: config.id,
        permissionSet: "P0GrantsRole",
        idc: { id: login.identityStoreId, region: login.idcRegion },
      });
      return {
        accessKeyId: creds.AWS_ACCESS_KEY_ID,
        secretAccessKey: creds.AWS_SECRET_ACCESS_KEY,
        sessionToken: creds.AWS_SESSION_TOKEN,
      };
    }
  } catch (e) {
    if (debug) print2(`IDC auth failed, falling back to env vars: ${e}`);
  }

  // Fall back to environment variables
  const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
  const sessionToken = process.env.AWS_SESSION_TOKEN;

  if (!accessKeyId || !secretAccessKey) {
    throw new Error(
      "AWS credentials not found. Either configure P0 IDC or export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
    );
  }
  if (debug) print2(`Using environment variable credentials`);
  return { accessKeyId, secretAccessKey, sessionToken };
}

// ============ SigV4 Signing ============

function signRequest(args: {
  method: string;
  url: string;
  body: string;
  region: string;
  service: string;
  credentials: SigningCredentials;
}): Record<string, string> {
  const { method, url, body, region, service, credentials } = args;
  const parsedUrl = new URL(url);

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.substring(0, 8);

  const host = parsedUrl.host;
  const canonicalUri = parsedUrl.pathname || "/";
  const canonicalQuerystring = parsedUrl.search.substring(1);
  const payloadHash = sha256(body);

  // Build canonical headers
  const signedHeadersList = ["host", "x-amz-date"];
  if (credentials.sessionToken) {
    signedHeadersList.push("x-amz-security-token");
  }
  signedHeadersList.sort();

  let canonicalHeaders = `host:${host}\nx-amz-date:${amzDate}\n`;
  if (credentials.sessionToken) {
    canonicalHeaders = `host:${host}\nx-amz-date:${amzDate}\nx-amz-security-token:${credentials.sessionToken}\n`;
  }

  const signedHeaders = signedHeadersList.join(";");

  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuerystring,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const algorithm = "AWS4-HMAC-SHA256";
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;

  const stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    sha256(canonicalRequest),
  ].join("\n");

  const signingKey = getSignatureKey(
    credentials.secretAccessKey,
    dateStamp,
    region,
    service
  );
  const signature = hmacHex(signingKey, stringToSign);

  const authorizationHeader =
    `${algorithm} ` +
    `Credential=${credentials.accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, ` +
    `Signature=${signature}`;

  const headers: Record<string, string> = {
    "x-amz-date": amzDate,
    Authorization: authorizationHeader,
  };

  if (credentials.sessionToken) {
    headers["x-amz-security-token"] = credentials.sessionToken;
  }

  return headers;
}

function sha256(data: string): string {
  return crypto.createHash("sha256").update(data, "utf8").digest("hex");
}

function hmac(key: Buffer | string, data: string): Buffer {
  return crypto.createHmac("sha256", key).update(data, "utf8").digest();
}

function hmacHex(key: Buffer, data: string): string {
  return crypto.createHmac("sha256", key).update(data, "utf8").digest("hex");
}

function getSignatureKey(
  key: string,
  dateStamp: string,
  region: string,
  service: string
): Buffer {
  const kDate = hmac(`AWS4${key}`, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  const kSigning = hmac(kService, "aws4_request");
  return kSigning;
}