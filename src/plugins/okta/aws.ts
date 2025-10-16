/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { retryWithSleep } from "../../common/retry";
import { parseXml } from "../../common/xml";
import { cached } from "../../drivers/auth";
import { Authn } from "../../types/identity";
import { assumeRoleWithSaml } from "../aws/assumeRole";
import { getAwsConfig } from "../aws/config";
import { AwsFederatedLogin, AwsItem } from "../aws/types";
import { fetchSamlAssertionForAws } from "./login";
import { flatten } from "lodash";

// Retry configuration for handling Okta eventual consistency
const ROLE_NOT_AVAILABLE_PATTERN = /^Role .+ not available\./;
const RETRY_ATTEMPTS = 5;
const INITIAL_RETRY_DELAY_MS = 1000;
const RETRY_MULTIPLIER = 2.0;
const MAX_RETRY_DELAY_MS = 10000;

/** Extracts all roles from a SAML assertion */
const rolesFromSaml = (account: string, saml: string) => {
  const samlText = Buffer.from(saml, "base64").toString("ascii");
  const samlObject = parseXml(samlText);
  const samlAttributes =
    samlObject["saml2p:Response"]["saml2:Assertion"][
      "saml2:AttributeStatement"
    ]["saml2:Attribute"];
  const roleAttribute = samlAttributes.find(
    (a: any) =>
      a._attributes.Name === "https://aws.amazon.com/SAML/Attributes/Role"
  );
  // Format:
  //   'arn:aws:iam::391052057035:saml-provider/p0dev-ext_okta_sso,arn:aws:iam::391052057035:role/path/to/role/SSOAmazonS3FullAccess'
  const arns = (
    flatten([roleAttribute?.["saml2:AttributeValue"]]) as string[]
  )?.map((r) => r.split(",")[1]!);
  const roles = arns
    .filter((r) => r.startsWith(`arn:aws:iam::${account}:role/`))
    .map((r) => r.split("/").slice(1).join("/"));
  return { arns, roles };
};

const isFederatedLogin = (
  config: AwsItem
): config is AwsItem & { login: AwsFederatedLogin } =>
  config.login?.type === "federated";

/** Retrieves the configured Okta SAML response for the specified account
 *
 * If no account is passed, and the organization only has one account configured,
 * assumes that account.
 */
const initOktaSaml = async (
  authn: Authn,
  account: string | undefined,
  debug?: boolean
) => {
  const { identity, config } = await getAwsConfig(authn, account, debug);
  if (!isFederatedLogin(config))
    throw `Account ${config.label ?? config.id} is not configured for Okta SAML login.`;
  const samlResponse = await fetchSamlAssertionForAws(identity, config.login);
  return {
    samlResponse,
    config,
    account: config.id,
  };
};

export const assumeRoleWithOktaSaml = async (
  authn: Authn,
  args: { accountId?: string; role: string },
  debug?: boolean
) =>
  await cached(
    `aws-okta-${args.accountId}-${args.role}`,
    async () => {
      // (Speculative) There could be a delay between Okta API role assignment and the role appearing
      // in the SAML assertions due to eventual consistency in Okta's distributed infrastructure.
      // Add retry logic to handle this race condition.
      return await retryWithSleep(
        async () => {
          const { account, config, samlResponse } = await initOktaSaml(
            authn,
            args.accountId,
            debug
          );
          const { roles } = rolesFromSaml(account, samlResponse);
          if (!roles.includes(args.role)) {
            throw `Role ${args.role} not available. Available roles:\n${roles.map((r) => `  ${r}`).join("\n")}`;
          }
          return await assumeRoleWithSaml({
            account,
            role: args.role,
            saml: {
              providerName: config.login.provider.identityProvider,
              response: samlResponse,
            },
          });
        },
        {
          shouldRetry: (error: unknown) => {
            // Only retry when the specific role is not available in the SAML response
            return (
              typeof error === "string" &&
              ROLE_NOT_AVAILABLE_PATTERN.test(error)
            );
          },
          retries: RETRY_ATTEMPTS,
          delayMs: INITIAL_RETRY_DELAY_MS,
          multiplier: RETRY_MULTIPLIER,
          maxDelayMs: MAX_RETRY_DELAY_MS,
          debug,
        }
      );
    },
    { duration: 3600e3 }
  );
