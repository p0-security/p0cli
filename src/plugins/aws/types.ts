/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Authn } from "../../types/identity";
import { PermissionSpec } from "../../types/request";
import { CliPermissionSpec } from "../../types/ssh";
import { CommonSshPermissionSpec } from "../ssh/types";

export type AwsCredentialFields = {
  AWS_ACCESS_KEY_ID: string;
  AWS_SECRET_ACCESS_KEY: string;
  AWS_SESSION_TOKEN: string;
  // AWS_SECURITY_TOKEN is the legacy version of AWS_SESSION_TOKEN. It does seem to take precedence over AWS_SESSION_TOKEN. The okta-aws-cli sets both: https://github.com/okta/okta-aws-cli/blob/f1e09eab509e295a7e7b3002d14f2a96b8c60914/internal/output/envvar.go#L49L63
  AWS_SECURITY_TOKEN: string;
};

export type AwsCredentials = AwsCredentialFields & {
  expiresAt?: number;
};

export type AwsIamLogin = {
  type: "iam";
  identity:
    | {
        type: "email";
      }
    | { type: "tag"; tagName: string };
};

export type AwsIdcLogin = {
  type: "idc";
  parent: string;
  idcArn: string;
  idcRegion: string;
  identityStoreId: string;
};

export type AwsFederatedLogin = {
  type: "federated";
  provider: {
    type: "okta";
    appId: string;
    identityProvider: string;
    method: {
      type: "saml";
    };
  };
};

export type AwsIamFederationLogin = {
  type: "aws-iam-federation";
  federation: string;
};

export type FederationProviderType = "okta" | "pingfederate" | "pingone";

/** Gets SAML responses for AWS from an identity provider's app */
export type SamlSource = {
  /** Gets a base64 SAML response for AWS */
  fetch: (authn: Authn, appId: string, debug?: boolean) => Promise<string>;
  /** Retries while the response doesn't list a new role yet */
  retries: number;
};

export type AwsIamFederationConfig = {
  federation: Record<
    string,
    { provider: { type: FederationProviderType; app: string } }
  >;
};

export type AwsLogin =
  | AwsFederatedLogin
  | AwsIamFederationLogin
  | AwsIamLogin
  | AwsIdcLogin;

export type AwsItemConfig = {
  label?: string;
  state: string;
  login?: AwsLogin;
};

export type AwsItem = { id: string } & AwsItemConfig;

export type AwsConfig = {
  "iam-write": Record<string, AwsItemConfig>;
};

// -- Specific AWS permission types

export type AwsSshPermission = CommonSshPermissionSpec & {
  provider: "aws";
  region: string;
  alias: string;
  // TODO: Remove 'AwsResourcePermission' after P0 backend data model update
  resource: Partial<AwsResourcePermission> & {
    instanceId: string;
    userName: string;
  };
};

type AwsResourcePermission = {
  account: string;
  accountId: string;
  arn: string;
  idcId: string | undefined;
  idcRegion: string | undefined;
  name: string;
};

// TODO: Remove after P0 backend data model update
type AwsResourceGenerated = { name: string };

type AwsIamFederationPoolSpec = PermissionSpec<
  "aws-iam-federation",
  Record<string, unknown>,
  { arn: string }
>;

/** The integration that holds each provider's federation apps */
export const FEDERATION_PROVIDER_INTEGRATIONS = {
  okta: "okta-aws-iam-federation",
  pingfederate: "pingfederate-aws-iam-federation",
  pingone: "pingone-aws-iam-federation",
} as const satisfies Record<FederationProviderType, string>;

type FederationProviderIntegration =
  (typeof FEDERATION_PROVIDER_INTEGRATIONS)[FederationProviderType];

type AwsIamFederationSpec = PermissionSpec<
  "aws-iam-federation",
  Record<string, unknown>,
  undefined,
  {
    [K in FederationProviderIntegration]?: PermissionSpec<
      K,
      Record<string, unknown>,
      undefined,
      { "aws-iam-federation"?: AwsIamFederationPoolSpec }
    >;
  }
>;

export type AwsResourcePermissionSpec = PermissionSpec<
  "aws",
  AwsResourcePermission,
  AwsResourceGenerated,
  { "aws-iam-federation"?: AwsIamFederationSpec }
>;

export type AwsSshGenerated = {
  hostKeys: string[];
  linuxUserName: string;
  publicKey: string;
  resource?: { name?: string };
};

export type AwsSshPermissionSpec = PermissionSpec<
  "ssh",
  AwsSshPermission,
  AwsSshGenerated,
  { aws: AwsResourcePermissionSpec }
>;

export type AwsSsh = CliPermissionSpec<AwsSshPermissionSpec, undefined>;

export type BaseAwsSshRequest = {
  linuxUserName: string;
  accountId: string;
  hostKeys: string[];
  region: string;
  id: string;
  type: "aws";
};

export type AwsSshRoleRequest = BaseAwsSshRequest & {
  role: string;
  access: "role";
};
export type AwsSshIdcRequest = BaseAwsSshRequest & {
  permissionSet: string;
  idc: { id: string; region: string };
  access: "idc";
};

export type AwsSshRequest = AwsSshIdcRequest | AwsSshRoleRequest;
