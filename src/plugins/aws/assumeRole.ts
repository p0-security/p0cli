import { urlEncode, validateResponse } from "../../common/fetch";
import { arnPrefix } from "./api";
import { AWS_API_VERSION } from "./api";

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
}) => {
  const params = urlEncode({
    Version: AWS_API_VERSION,
    Action: "AssumeRoleWithSAML",
    RoleArn: `${arnPrefix(args.account)}:role/${args.role}`,
    PrincipalArn: `${arnPrefix(args.account)}:saml-provider/${
      args.saml.providerName
    }`,
    // Note that, despite the name, AWS actually expects a SAML Response
    SAMLAssertion: args.saml.response,
  });
  const url = `https://sts.amazonaws.com?${params}`;
  const response = await fetch(url, {
    method: "GET",
  });
  await validateResponse(response);
  return await response.text();
};
