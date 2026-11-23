/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { retryWithSleep } from "../../common/retry";
import { parseXml } from "../../common/xml";
import { fetchIntegrationConfig } from "../../drivers/api";
import { cached } from "../../drivers/auth";
import { Authn } from "../../types/identity";
import { fetchSamlAssertionForAws } from "../okta/login";
import { assumeRoleWithSaml } from "./assumeRole";
import { getAwsConfig } from "./config";
import {
  AwsFederatedLogin,
  AwsIamFederationConfig,
  AwsIamFederationLogin,
  AwsItem,
} from "./types";
import { flatten } from "lodash";

// Retry configuration for handling Okta eventual consistency
// With exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s, 30s, 30s... ≈ 5 minutes total
const ROLE_NOT_AVAILABLE_PATTERN = /^Role .+ not available\./;
const RETRY_ATTEMPTS = 14;
const INITIAL_RETRY_DELAY_MS = 1000;
const RETRY_MULTIPLIER = 2.0;
const MAX_RETRY_DELAY_MS = 30000;

// Matches IAM role ARNs in known AWS partitions (commercial or GovCloud).
// Capture group 1: partition; capture group 2: account ID.
const ROLE_ARN_PATTERN = /^arn:(aws|aws-us-gov):iam::([^:]+):role\//;

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
  const pairs = (
    flatten([roleAttribute?.["saml2:AttributeValue"]]) as string[]
  )?.map((r) => r.split(","));
  const arns = pairs.map((pair) => pair[1]!);
  const matched = pairs
    .map(([provider, arn]) => ({
      provider: provider!,
      arn: arn!,
      match: ROLE_ARN_PATTERN.exec(arn!),
    }))
    .filter(
      (x): x is { provider: string; arn: string; match: RegExpExecArray } =>
        x.match !== null && x.match[2] === account
    );
  // Partition must flow to STS so we hit the right endpoint and emit ARNs in the matching partition.
  const partition = matched[0]?.match[1] ?? "aws";
  const afterType = (arn: string) => arn.split("/").slice(1).join("/");
  const roles = matched.map(({ arn }) => afterType(arn));
  const samlProviders: Record<string, string> = Object.fromEntries(
    matched.map(({ provider, arn }) => [afterType(arn), afterType(provider)])
  );
  return { arns, roles, partition, samlProviders };
};

const isFederatedLogin = (
  config: AwsItem
): config is AwsItem & {
  login: AwsFederatedLogin | AwsIamFederationLogin;
} =>
  config.login?.type === "federated" ||
  config.login?.type === "aws-iam-federation";

/** Gets the Okta app ID of an AWS IAM Federation */
const federationOktaAppId = async (
  authn: Authn,
  federation: string,
  debug?: boolean
) => {
  const { config } = await fetchIntegrationConfig<{
    config: AwsIamFederationConfig;
  }>(authn, "aws-iam-federation", debug);
  const provider = config?.federation?.[federation]?.provider;
  if (!provider) throw `AWS IAM Federation ${federation} is not installed.`;
  if (provider.type !== "okta")
    throw `The P0 CLI can't sign in to AWS through ${provider.type}. Sign in to AWS from your identity provider's app portal.`;
  return provider.app;
};

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
  const appId =
    config.login.type === "federated"
      ? config.login.provider.appId
      : await federationOktaAppId(authn, config.login.federation, debug);
  const samlResponse = await fetchSamlAssertionForAws(identity, appId, debug);
  return {
    samlResponse,
    config,
    account: config.id,
  };
};

export const assumeRoleWithSamlLogin = async (
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
          const { roles, partition, samlProviders } = rolesFromSaml(
            account,
            samlResponse
          );
          if (!roles.includes(args.role)) {
            throw `Role ${args.role} not available. Available roles:\n${roles.map((r) => `  ${r}`).join("\n")}`;
          }
          return await assumeRoleWithSaml({
            account,
            partition,
            role: args.role,
            saml: {
              providerName:
                config.login.type === "federated"
                  ? config.login.provider.identityProvider
                  : samlProviders[args.role]!,
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
