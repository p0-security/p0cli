import { parseXml } from "../../common/xml";
import { authenticate } from "../../drivers/auth";
import { guard } from "../../drivers/firestore";
import { getAwsConfig } from "../../plugins/aws/config";
import { AwsItemConfig, AwsOktaSamlUidLocation } from "../../plugins/aws/types";
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
        guard(oktaAwsListRoles)
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
        guard(oktaAwsAssumeRole)
      )
      .demandCommand(1)
  );

const isOktaSamlConfig = (
  config: AwsItemConfig
): config is AwsItemConfig & { uidLocation: AwsOktaSamlUidLocation } =>
  config.uidLocation?.id === "okta_saml_sso";

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
  if (!isOktaSamlConfig(config))
    throw `Account ${config.account.description} is not configured for Okta SAML login.`;
  const samlResponse = await getSamlResponse(identity, config.uidLocation);
  return {
    samlResponse,
    config,
    account: config.account.id,
  };
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
  if (isTty) console.error("Execute the following commands:\n");
  const indent = isTty ? "  " : "";
  console.log(
    Object.entries(awsCredential)
      .map(([key, value]) => `${indent}export ${key}=${value}`)
      .join("\n")
  );
  if (isTty)
    console.error(`
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
  const samlText = Buffer.from(samlResponse, "base64").toString("ascii");
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
  const isTty = sys.writeOutputIsTTY?.();
  if (isTty) console.error(`Your available roles for account ${account}:`);
  if (!roles?.length) {
    const accounts = uniq(arns.map((a) => a.split(":")[4])).sort();
    throw `No roles found. You have roles on these accounts:\n${accounts.join(
      "\n"
    )}`;
  }
  const indent = isTty ? "  " : "";
  console.log(roles.map((r) => `${indent}${r}`).join("\n"));
};
