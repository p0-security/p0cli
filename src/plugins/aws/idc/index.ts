/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { retryWithBackOff } from "../../../common/backoff";
import { validateResponse } from "../../../common/fetch";
import { cached } from "../../../drivers/auth";
import { print2 } from "../../../drivers/stdio";
import { ClientRegistrationInfo } from "../../../types/aws/oidc";
import { sleep } from "../../../util";
import { DEVICE_GRANT_TYPE } from "../../oidc/login";
import { AwsCredentials } from "../types";
import open from "open";

export const fetchClientSecrets = async (
  region: string
): Promise<ClientRegistrationInfo> =>
  await cached(
    `aws-idc-client`,
    async (): Promise<ClientRegistrationInfo> => {
      const init = {
        method: "POST",
        body: JSON.stringify({
          clientName: "p0Cli",
          clientType: "public",
          grantTypes: [DEVICE_GRANT_TYPE],
        }),
      };
      const response = await fetch(
        `https://oidc.${region}.amazonaws.com/client/register`,
        init
      );
      return await response.json();
    },
    {
      duration: 6.48e9, // the token has lifetime of 90 days, just to be cautious we have set the cache duration to 75 days
    }
  );

export const fetchOIDCDeviceAuthorization = async (
  clientCredentials: { clientId: string; clientSecret: string },
  idc: { id: string; region: string }
) =>
  await cached(
    `aws-idc-device-authorization`,
    async () => {
      // curl -X POST https://oidc.eu-central-1.amazonaws.com/device_authorization -d '{"clientId": "R-j5yN-4-TPNs...tMQ", "clientSecret": "eyJr...x74", "startUrl": "https://example.awsapps.com/start"}'
      const { clientId, clientSecret } = clientCredentials;
      const { id, region } = idc;

      const init = {
        method: "POST",
        body: JSON.stringify({
          clientId,
          clientSecret,
          startUrl: `https://${id}.awsapps.com/start`,
        }),
      };

      const response = await fetch(
        `https://oidc.${region}.amazonaws.com/device_authorization`,
        init
      );

      const authorizeResponse = await response.json();

      print2(`Please use the opened browser window to continue your idc device authorization.
  
    When prompted, confirm that aws idc page displays this code:
    
      ${authorizeResponse.userCode}
    
    Waiting for authorization...
    `);
      void open(authorizeResponse.verificationUriComplete);
      const oidcResponse = await waitForActivation(
        clientCredentials,
        idc,
        authorizeResponse
      );
      return oidcResponse;
    },
    { duration: 2.16e7 } // oidc response expires in 8 hours. We are caching it for 6 hours
  );

export type AWSTokenResponse = {
  accessToken: string;
  expiresIn: number;
  idToken: string;
  refreshToken: string;
  tokenType: string;
};

const fetchOidcToken = async (
  clientCredentials: { clientId: string; clientSecret: string },
  idc: { id: string; region: string },
  authorizeResponse: any
) => {
  //curl -X POST https://oidc.eu-central-1.amazonaws.com/token -d '{"clientId": "R-j5yN-4-TPNs...tMQ", "clientSecret": "eyJr...x74", "deviceCode": "8Acq...DUg", "grantType": "urn:ietf:params:oauth:grant-type:device_code"}'

  const { clientId, clientSecret } = clientCredentials;
  const { region } = idc;
  const init = {
    method: "POST",
    body: JSON.stringify({
      clientId,
      clientSecret,
      deviceCode: authorizeResponse.deviceCode,
      grantType: DEVICE_GRANT_TYPE,
    }),
  };
  const response = await fetch(
    `https://oidc.${region}.amazonaws.com/token`,
    init
  );
  if (!response.ok) {
    if (response.status === 400) {
      const data = await response.json();
      if (data.error === "authorization_pending") return undefined;
    }
    await validateResponse(response);
  }
  return (await response.json()) as AWSTokenResponse;
};

const waitForActivation = async (
  clientCredentials: { clientId: string; clientSecret: string },
  idc: { id: string; region: string },
  authorizeResponse: any
) => {
  const start = Date.now();
  while (Date.now() - start <= authorizeResponse.expiresIn * 1e3) {
    const response = await fetchOidcToken(
      clientCredentials,
      idc,
      authorizeResponse
    );
    if (!response) await sleep(authorizeResponse.interval * 1e3);
    else return response;
  }
  throw "Expired awaiting in-browser authorization.";
};

const fetchAWSCredentials = async (
  oidcResponse: AWSTokenResponse,
  idc: { id: string; region: string },
  request: { account?: string; permissionSet: string }
) => {
  //curl 'https://portal.sso.eu-central-1.amazonaws.com/federation/credentials?account_id=999999999999&role_name=MyIamRoleName' -H 'x-amz-sso_bearer_token: eyJl...Blw'
  return await retryWithBackOff(
    async () => {
      const init = {
        method: "GET",
        headers: {
          "x-amz-sso_bearer_token": oidcResponse.accessToken,
        },
      };
      const { account, permissionSet } = request;
      const { region } = idc;
      const response = await fetch(
        `https://portal.sso.${region}.amazonaws.com/federation/credentials?account_id=${account}&role_name=${permissionSet}`,
        init
      );
      if (response.ok) return await response.json();
      throw new Error(
        `Failed to fetch AWS credentials: ${response.statusText}`
      );
    },
    () => true,
    3
  );
};

export const assumeRoleWithIdc = async (
  args: { account?: string; role: string },
  idc: { id: string; region: string },
  request: { account?: string; permissionSet: string }
): Promise<AwsCredentials> =>
  await cached(
    `aws-idc-${args.account}-${args.role}`,
    async () => {
      const { region } = idc;
      // fetch aws client secrets
      const clientSecrets = await fetchClientSecrets(region);
      const oidcResponse = await fetchOIDCDeviceAuthorization(
        clientSecrets,
        idc
      );

      print2(`OIDC Response: ${JSON.stringify(oidcResponse, null, 2)}`);

      // fetch device authorization
      const credentials = await fetchAWSCredentials(oidcResponse, idc, request);
      print2(`${JSON.stringify(credentials, null, 2)}`);
      return {
        AWS_ACCESS_KEY_ID: credentials.roleCredentials.accessKeyId,
        AWS_SECRET_ACCESS_KEY: credentials.roleCredentials.secretAccessKey,
        AWS_SESSION_TOKEN: credentials.roleCredentials.sessionToken,
        AWS_SECURITY_TOKEN: credentials.roleCredentials.securityToken ?? "", // portal does not return this value
      };
    },
    { duration: 3600e3 }
  );
