/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { retryWithSleep } from "../../common/retry";
import { samlAttributeValues } from "../../common/saml";
import { fetchIntegrationConfig } from "../../drivers/api";
import { cached } from "../../drivers/auth";
import { Authn } from "../../types/identity";
import { oktaSamlSource } from "../okta/login";
import { pingFederateSamlSource } from "../pingfederate/aws";
import { assumeRoleWithSaml } from "./assumeRole";
import { getAwsConfig } from "./config";
import {
  AwsFederatedLogin,
  AwsIamFederationConfig,
  AwsIamFederationLogin,
  AwsItem,
  FederationProviderType,
  SamlSource,
} from "./types";
import { sortBy } from "lodash";

// Backoff: 1s, 2s, 4s, 8s, 16s, 30s, 30s, 30s...
const ROLE_NOT_AVAILABLE_PATTERN = /^Role .+ not available\./;
const INITIAL_RETRY_DELAY_MS = 1000;
const RETRY_MULTIPLIER = 2.0;
const MAX_RETRY_DELAY_MS = 30000;

// Matches IAM role ARNs in known AWS partitions (commercial or GovCloud).
// Capture group 1: partition; capture group 2: account ID.
const ROLE_ARN_PATTERN = /^arn:(aws|aws-us-gov):iam::([^:]+):role\//;

/** Extracts all roles from a SAML assertion */
const rolesFromSaml = (account: string, saml: string) => {
  // Format:
  //   'arn:aws:iam::391052057035:saml-provider/p0dev-ext_okta_sso,arn:aws:iam::391052057035:role/path/to/role/SSOAmazonS3FullAccess'
  // AWS accepts the two ARNs in either order: Okta puts the provider first,
  // PingFederate puts the role first.
  const pairs = samlAttributeValues(
    saml,
    "https://aws.amazon.com/SAML/Attributes/Role"
  ).map((r) => sortBy(r.split(","), (arn) => !arn.includes(":saml-provider/")));
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

const samlSources: Record<FederationProviderType, SamlSource | undefined> = {
  okta: oktaSamlSource,
  pingfederate: pingFederateSamlSource,
  pingone: undefined,
};

/** Gets the identity provider's app of an AWS IAM Federation */
const federationApp = async (
  authn: Authn,
  federation: string,
  debug?: boolean
) => {
  const { config } = await fetchIntegrationConfig<{
    config: AwsIamFederationConfig;
  }>(authn, "aws-iam-federation", debug);
  const provider = config?.federation?.[federation]?.provider;
  if (!provider) throw `AWS IAM Federation ${federation} is not installed.`;
  return provider;
};

/** Gets the federation app that signs in to the specified account
 *
 * If no account is passed, and the organization only has one account configured,
 * assumes that account.
 */
const initSamlApp = async (
  authn: Authn,
  account: string | undefined,
  debug?: boolean
) => {
  const { config } = await getAwsConfig(authn, account, debug);
  if (!isFederatedLogin(config))
    throw `Account ${config.label ?? config.id} is not configured for SAML login.`;
  const provider =
    config.login.type === "federated"
      ? { type: "okta" as const, app: config.login.provider.appId }
      : await federationApp(authn, config.login.federation, debug);
  const source = samlSources[provider.type];
  if (!source)
    throw `The P0 CLI can't sign in to AWS through ${provider.type}. Sign in to AWS from your identity provider's app portal.`;
  return { account: config.id, appId: provider.app, config, source };
};

export const assumeRoleWithSamlLogin = async (
  authn: Authn,
  args: { accountId?: string; role: string },
  debug?: boolean
) =>
  await cached(
    `aws-saml-${args.accountId}-${args.role}`,
    async () => {
      const { account, appId, config, source } = await initSamlApp(
        authn,
        args.accountId,
        debug
      );
      return await retryWithSleep(
        async () => {
          const samlResponse = await source.fetch(authn, appId, debug);
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
          retries: source.retries,
          delayMs: INITIAL_RETRY_DELAY_MS,
          multiplier: RETRY_MULTIPLIER,
          maxDelayMs: MAX_RETRY_DELAY_MS,
          debug,
        }
      );
    },
    { duration: 3600e3 }
  );
