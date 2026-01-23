/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { validateResponse } from "../../../common/fetch";
import { retryWithSleep } from "../../../common/retry";
import { cached } from "../../../drivers/auth";
import {
  AWSAuthorizeResponse,
  AWSClientInformation,
  AWSTokenResponse,
} from "../../../types/aws/oidc";
import { OidcLoginSteps } from "../../../types/oidc";
import { DEVICE_GRANT_TYPE, oidcLogin } from "../../oidc/login";
import { AwsCredentials } from "../types";

const HOURS = 60 * 60 * 1000;
const DAYS = 24 * HOURS;

const AWS_TOKEN_EXPIRY = 1 * HOURS;
const AWS_CLIENT_TOKEN_EXPIRY = 90 * DAYS; // the token has lifetime of 90 days
const AWS_SSO_SCOPES = ["sso:account:access"];

export const registerClient = async (
  region: string
): Promise<AWSClientInformation> =>
  await cached(
    "aws-idc-client",
    async (): Promise<AWSClientInformation> => {
      const init = {
        method: "POST",
        body: JSON.stringify({
          clientName: "p0Cli",
          clientType: "public",
          grantTypes: [DEVICE_GRANT_TYPE],
          scopes: AWS_SSO_SCOPES,
        }),
      };
      const response = await fetch(
        `https://oidc.${region}.amazonaws.com/client/register`,
        init
      );
      return await response.json();
    },
    { duration: AWS_CLIENT_TOKEN_EXPIRY },
    (data) =>
      data.clientSecretExpiresAt
        ? data.clientSecretExpiresAt < Date.now()
        : true
  );

const awsIdcHelpers = (
  clientCredentials: { clientId: string; clientSecret: string },
  idc: { id: string; region: string }
) => {
  const { clientId, clientSecret } = clientCredentials;
  const { id, region } = idc;

  // The start url can be customized with a subdomain. Here only the default is supported.
  const buildStartUrl = () =>
    region.includes("us-gov")
      ? `https://start.us-gov-home.awsapps.com/directory/${id}`
      : `https://${id}.awsapps.com/start`;

  const buildOidcAuthorizeRequest = () => ({
    init: {
      method: "POST",
      body: JSON.stringify({
        clientId,
        clientSecret,
        startUrl: buildStartUrl(),
      }),
    },
    url: `https://oidc.${region}.amazonaws.com/device_authorization`,
  });
  const buildIdcTokenRequest = (authorizeResponse: AWSAuthorizeResponse) => ({
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
  });
  /**
   * Exchanges the oidc token for AWS credentials for a given account and permission set
   * @param oidcResponse oidc token response fot he oidc /token endpoint
   * @param request accountId and permissionSet to exchange for AWS credentials
   * @returns
   */
  const exchangeForAwsCredentials = async (
    oidcResponse: AWSTokenResponse,
    request: { accountId?: string; permissionSet: string }
  ) => {
    // There is a delay in between aws issuing the sso token and it being available for exchange for AWS credentials
    // When exchanging token immediately, an "unauthorized" may will be thrown, so retry with sleep.

    return await retryWithSleep(
      async () => {
        const init = {
          method: "GET",
          headers: {
            "x-amz-sso_bearer_token": oidcResponse.accessToken,
          },
        };
        const { accountId, permissionSet } = request;
        if (accountId === undefined)
          throw new Error(
            "Could not find an AWS account ID for this access request"
          );

        const params = new URLSearchParams();
        params.append("account_id", accountId);
        params.append("role_name", permissionSet);
        const response = await fetch(
          `https://portal.sso.${region}.amazonaws.com/federation/credentials?${params.toString()}`,
          init
        );
        if (!response.ok)
          throw new Error(
            `Timed out fetching AWS credentials. Try again, and if this issue persists, contact support@p0.dev.`
          );
        return await response.json();
      },
      { retries: 4 }
    );
  };

  return {
    loginSteps: {
      providerType: "aws-oidc",
      validateResponse,
      buildAuthorizeRequest: buildOidcAuthorizeRequest,
      buildTokenRequest: buildIdcTokenRequest,
      processAuthzExpiry: (authorize) => ({
        expires_in: authorize.expiresIn,
        interval: authorize.interval,
      }),
      processAuthzResponse: (authorize) => ({
        user_code: authorize.userCode,
        verification_uri_complete: authorize.verificationUriComplete,
      }),
    } as OidcLoginSteps<AWSAuthorizeResponse>,
    exchangeForAwsCredentials,
  };
};

/**
 * Returns AWS credentials for the specified account and permission set for the authorized user
 * @param args accountId, permissionSet and idc to assume role associated with the permission set
 * @returns
 */
export const assumeRoleWithIdc = async (args: {
  accountId?: string;
  permissionSet: string;
  idc: { id: string; region: string };
}): Promise<AwsCredentials> =>
  await cached(
    `aws-idc-${args.accountId}-${args.permissionSet}`,
    async () => {
      const { idc } = args;
      const { region } = idc;
      const clientSecrets = await registerClient(region);

      const { loginSteps, exchangeForAwsCredentials } = awsIdcHelpers(
        clientSecrets,
        idc
      );

      const oidcResponse = await cached(
        "aws-idc-device-authorization",
        async () => {
          const data = await oidcLogin<AWSAuthorizeResponse, AWSTokenResponse>(
            loginSteps
          );
          return { ...data, expiresAt: Date.now() + data.expiresIn * 1e3 };
        },
        { duration: AWS_TOKEN_EXPIRY },
        (data) => (data.expiresAt ? data.expiresAt < Date.now() : true)
      );

      const credentials = await exchangeForAwsCredentials(oidcResponse, {
        accountId: args.accountId,
        permissionSet: args.permissionSet,
      });

      return {
        AWS_ACCESS_KEY_ID: credentials.roleCredentials.accessKeyId,
        AWS_SECRET_ACCESS_KEY: credentials.roleCredentials.secretAccessKey,
        AWS_SESSION_TOKEN: credentials.roleCredentials.sessionToken,
        AWS_SECURITY_TOKEN: credentials.roleCredentials.sessionToken, // portal does not return security value, setting it to session token for safety
        expiresAt: credentials.roleCredentials.expiration,
      };
    },
    { duration: AWS_TOKEN_EXPIRY },
    (data) => (data.expiresAt ? data.expiresAt < Date.now() : true)
  );
