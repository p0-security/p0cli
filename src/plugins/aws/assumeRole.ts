import { urlEncode, validateResponse } from "../../common/fetch";
import { parseXml } from "../../common/xml";
import { arnPrefix } from "./api";
import { AWS_API_VERSION } from "./api";
import { AwsCredentials } from "./types";
import { AssumeRoleCommand, STSClient } from "@aws-sdk/client-sts";

const roleArn = (args: { account: string; role: string }) =>
  `${arnPrefix(args.account)}:role/${args.role}`;

const stsAssume = async (
  params: Record<string, string>
): Promise<AwsCredentials> => {
  const url = `https://sts.amazonaws.com?${urlEncode(params)}`;
  const response = await fetch(url, {
    method: "GET",
  });
  await validateResponse(response);
  const stsXml = await response.text();
  const stsObject = parseXml(stsXml);
  const stsCredentials =
    stsObject.AssumeRoleWithSAMLResponse.AssumeRoleWithSAMLResult.Credentials;
  return {
    AWS_ACCESS_KEY_ID: stsCredentials.AccessKeyId,
    AWS_SECRET_ACCESS_KEY: stsCredentials.SecretAccessKey,
    AWS_SESSION_TOKEN: stsCredentials.SessionToken,
  };
};

/** Assumes an AWS role via SAML login */
export const assumeRoleWithSaml = async (args: {
  /** An AWS account identifier */
  account: string;
  /** The account-specific role name requested */
  role: string;
  saml: {
    /** The SAML Identity Provider name in AWS IAM */
    providerName: string;
    /** A base64-encoded SAML response document */
    response: string;
  };
}): Promise<AwsCredentials> => {
  const params = {
    Version: AWS_API_VERSION,
    Action: "AssumeRoleWithSAML",
    RoleArn: roleArn(args),
    PrincipalArn: `${arnPrefix(args.account)}:saml-provider/${
      args.saml.providerName
    }`,
    // Note that, despite the name, AWS actually expects a SAML Response
    SAMLAssertion: args.saml.response,
  };
  return await stsAssume(params);
};

/** Assumes an AWS role using AWS credentials */
export const assumeRole = async (args: {
  account: string;
  region: string;
  role: string;
  roleSessionName: string;
  credentials: AwsCredentials;
}): Promise<AwsCredentials> => {
  const cli = new STSClient({
    apiVersion: AWS_API_VERSION,
    region: args.region,
    credentials: {
      accessKeyId: args.credentials.AWS_ACCESS_KEY_ID,
      secretAccessKey: args.credentials.AWS_SECRET_ACCESS_KEY,
      sessionToken: args.credentials.AWS_SESSION_TOKEN,
    },
  });
  const { Credentials } = await cli.send(
    new AssumeRoleCommand({
      RoleArn: roleArn(args),
      RoleSessionName: args.roleSessionName,
    })
  );
  if (!Credentials) throw "AWS did not return role credentials";
  if (
    !Credentials.AccessKeyId ||
    !Credentials.SecretAccessKey ||
    !Credentials.SessionToken
  )
    throw "AWS returned incomplete role session credentials";
  return {
    AWS_ACCESS_KEY_ID: Credentials.AccessKeyId,
    AWS_SECRET_ACCESS_KEY: Credentials.SecretAccessKey,
    AWS_SESSION_TOKEN: Credentials.SessionToken,
  };
};
