/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { retryWithBackOff } from "../../../common/backoff";
import { cached } from "../../../drivers/auth";
import { print2 } from "../../../drivers/stdio";
import {
  AWSTokenResponse,
  ClientRegistrationInfo,
} from "../../../types/aws/oidc";
import { OidcLoginSteps } from "../../../types/oidc";
import {
  authorize,
  DEVICE_GRANT_TYPE,
  fetchOidcToken,
  oidcLogin,
  waitForActivation,
} from "../../oidc/login";
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
    },
    (data) => data.clientSecretExpiresAt < Date.now()
  );

const fetchAWSCredentials = async (
  oidcResponse: AWSTokenResponse & { expiresAt: number },
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

const idcRequestBuilder = (
  clientCredentials: { clientId: string; clientSecret: string },
  idc: { id: string; region: string },
  authorizeResponse: any
) => {
  const { clientId, clientSecret } = clientCredentials;
  const { region } = idc;

  return {
    url: `https://oidc.${region}.amazonaws.com/token`,
    init: {
      method: "POST",
      body: JSON.stringify({
        clientId,
        clientSecret,
        deviceCode: authorizeResponse.deviceCode,
        grantType: DEVICE_GRANT_TYPE,
      }),
    },
  };
};

const idcAuthorizeRequestBuilder = (
  clientCredentials: { clientId: string; clientSecret: string },
  idc: { id: string; region: string }
) => {
  const { clientId, clientSecret } = clientCredentials;
  const { id, region } = idc;

  return {
    init: {
      method: "POST",
      body: JSON.stringify({
        clientId,
        clientSecret,
        startUrl: `https://${id}.awsapps.com/start`,
      }),
    },
    url: `https://oidc.${region}.amazonaws.com/device_authorization`,
  };
};

export const idcLoginSteps: (
  clientCredentials: { clientId: string; clientSecret: string },
  idc: { id: string; region: string }
) => OidcLoginSteps<any, AWSTokenResponse> = (
  clientCredentials: { clientId: string; clientSecret: string },
  idc: { id: string; region: string }
) => ({
  authorize: async () => {
    const authorizeResponse = await authorize<any>(
      idcAuthorizeRequestBuilder(clientCredentials, idc)
    );
    print2(`Please use the opened browser window to continue your idc device authorization.
  
      When prompted, confirm that aws idc page displays this code:
      
        ${authorizeResponse.userCode}
      
      Waiting for authorization...
      `);
    void open(authorizeResponse.verificationUriComplete);
    return authorizeResponse;
  },
  activate: async (authorizeResponse) =>
    await waitForActivation<any, AWSTokenResponse>(authorizeResponse)(
      (authorize) => authorize.expiresIn,
      (authorize) =>
        fetchOidcToken<AWSTokenResponse>(
          idcRequestBuilder(clientCredentials, idc, authorize)
        )
    ),
});

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
      const oidcResponse = await cached(
        `aws-idc-device-authorization`,
        async () => {
          const data = await oidcLogin(idcLoginSteps(clientSecrets, idc));
          return { ...data, expiresAt: Date.now() + data.expiresIn * 1e3 };
        },
        {
          duration: 3600e3,
        },
        (data) => data.expiresAt < Date.now()
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
        expiresAt: credentials.roleCredentials.expiration,
      };
    },
    { duration: 3600e3 },
    (data) => data.expiresAt < Date.now()
  );
