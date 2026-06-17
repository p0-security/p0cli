/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { validateResponse } from "../../common/fetch";
import { parseXml } from "../../common/xml";
import { arnPrefix, stsEndpoint } from "./api";
import { AWS_API_VERSION } from "./api";
import { AwsCredentials } from "./types";

const roleArn = (args: { account: string; partition: string; role: string }) =>
  `${arnPrefix(args.account, args.partition)}:role/${args.role}`;

const stsAssume = async (
  partition: string,
  params: Record<string, string>
): Promise<AwsCredentials> => {
  // Regional endpoints issue version-2 tokens, which are valid in all AWS regions.
  // The us-east-1 and eu-south-1 regional endpoints are the only ones that are always on.
  // Use the us-east-1 as it should be closer to most users.
  // Calling the global endpoints issues version-1 tokens, which are only valid in default regions.
  // See https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_region-endpoints.html
  const url = stsEndpoint(partition);
  const response = await fetch(url, {
    method: "POST",
    body: new URLSearchParams(params),
  });
  await validateResponse(response);
  const stsXml = await response.text();
  const stsObject = parseXml(stsXml);
  const stsCredentials =
    stsObject.AssumeRoleWithSAMLResponse.AssumeRoleWithSAMLResult.Credentials;
  // Date.parse returns NaN for a missing/malformed Expiration. Normalize that to
  // undefined so downstream consumers treat it as "expiry unknown"
  const parsedExpiration = Date.parse(stsCredentials.Expiration);
  const expiresAt = Number.isNaN(parsedExpiration)
    ? undefined
    : parsedExpiration;
  return {
    AWS_ACCESS_KEY_ID: stsCredentials.AccessKeyId,
    AWS_SECRET_ACCESS_KEY: stsCredentials.SecretAccessKey,
    AWS_SESSION_TOKEN: stsCredentials.SessionToken,
    AWS_SECURITY_TOKEN: stsCredentials.SessionToken,
    expiresAt, // epoch ms, or undefined if AWS gave us an unparseable Expiration
  };
};

/** Assumes an AWS role via SAML login */
export const assumeRoleWithSaml = async (args: {
  /** An AWS account identifier */
  account: string;
  /** AWS partition for the role (e.g. "aws", "aws-us-gov", "aws-cn"). Defaults to "aws". */
  partition?: string;
  /** The account-specific role name requested */
  role: string;
  saml: {
    /** The SAML Identity Provider name in AWS IAM */
    providerName: string;
    /** A base64-encoded SAML response document */
    response: string;
  };
}): Promise<AwsCredentials> => {
  const partition = args.partition ?? "aws";
  const params = {
    Version: AWS_API_VERSION,
    Action: "AssumeRoleWithSAML",
    RoleArn: roleArn({ ...args, partition }),
    PrincipalArn: `${arnPrefix(args.account, partition)}:saml-provider/${
      args.saml.providerName
    }`,
    // Note that, despite the name, AWS actually expects a SAML Response
    SAMLAssertion: args.saml.response,
  };
  return await stsAssume(partition, params);
};
