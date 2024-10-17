/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { parseXml } from "../../common/xml";
import { authenticate } from "../../drivers/auth";
import { fsShutdownGuard } from "../../drivers/firestore";
import { print1, print2 } from "../../drivers/stdio";
import { getAwsConfig } from "../../plugins/aws/config";
import { AwsFederatedLogin, AwsItem } from "../../plugins/aws/types";
import { assumeRoleWithOktaSaml } from "../../plugins/okta/aws";
import { getSamlResponse } from "../../plugins/okta/login";
import { Authn } from "../../types/identity";
import { flatten, identity, uniq } from "lodash";
import { sys } from "typescript";
import yargs from "yargs";

export const role = (yargs: yargs.Argv<{ account: string | undefined }>) =>
  yargs.command("role", "Interact with AWS roles", (yargs) =>
    yargs
      .command(
        "ls",
        "List available AWS roles",
        identity,
        // TODO: select based on uidLocation
        fsShutdownGuard(oktaAwsListRoles)
      )
      .command(
        "assume <role>",
        "Assume an AWS role",
        (y: yargs.Argv<{ account: string | undefined }>) =>
          y.positional("role", {
            type: "string",
            demandOption: true,
            describe: "An AWS role name",
          }),
        // TODO: select based on uidLocation
        fsShutdownGuard(oktaAwsAssumeRole)
      )
      .demandCommand(1)
  );

const isFederatedLogin = (
  config: AwsItem
): config is AwsItem & { login: AwsFederatedLogin } =>
  config.login?.type === "federated";

/** Retrieves the configured Okta SAML response for the specified account
 *
 * If no account is passed, and the organization only has one account configured,
 * assumes that account.
 */
export const initOktaSaml = async (
  authn: Authn,
  account: string | undefined
) => {
  const { identity, config } = await getAwsConfig(authn, account);
  if (!isFederatedLogin(config))
    throw `Account ${config.label ?? config.id} is not configured for Okta SAML login.`;
  const samlResponse = await getSamlResponse(identity, config.login);
  return {
    samlResponse,
    config,
    account: config.id,
  };
};

/** Extracts all roles from a SAML assertion */
export const rolesFromSaml = (account: string, saml: string) => {
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

/** Assumes a role in AWS via Okta SAML federation.
 *
 * Prerequisites:
 * - AWS is configured with a SAML identity provider
 * - This identity provider is integrated with a
 *   "AWS SAML Account Federation" app in Okta
 * - The AWS SAML identity provider name, Okta domain,
 *   and Okta SAML app identifier are all contained in
 *   the user's identity blob
 * - The requested role is assigned to the user in Okta
 */
const oktaAwsAssumeRole = async (args: { account?: string; role: string }) => {
  const authn = await authenticate();
  const awsCredential = await assumeRoleWithOktaSaml(authn, args);
  const isTty = sys.writeOutputIsTTY?.();
  if (isTty) print2("Execute the following commands:\n");
  const indent = isTty ? "  " : "";
  print1(
    Object.entries(awsCredential)
      .map(([key, value]) => `${indent}export ${key}=${value}`)
      .join("\n")
  );
  if (isTty)
    print2(`
Or, populate these environment variables using BASH command substitution:

  $(p0 aws${args.account ? ` --account ${args.account}` : ""} role assume ${
    args.role
  })
`);
};

/** Lists assigned AWS roles for this user on this account */
const oktaAwsListRoles = async (args: { account?: string }) => {
  const authn = await authenticate();
  const { account, samlResponse } = await initOktaSaml(authn, args.account);
  const { arns, roles } = rolesFromSaml(account, samlResponse);
  const isTty = sys.writeOutputIsTTY?.();
  if (isTty) print2(`Your available roles for account ${account}:`);
  if (!roles?.length) {
    const accounts = uniq(arns.map((a) => a.split(":")[4])).sort();
    throw `No roles found. You have roles on these accounts:\n${accounts.join(
      "\n"
    )}`;
  }
  const indent = isTty ? "  " : "";
  print1(roles.map((r) => `${indent}${r}`).join("\n"));
};
