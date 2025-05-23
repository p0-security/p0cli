/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { PermissionSpec } from "../../types/request";
import { CliPermissionSpec } from "../../types/ssh";
import { CommonSshPermissionSpec } from "../ssh/types";

export type AwsCredentials = {
  AWS_ACCESS_KEY_ID: string;
  AWS_SECRET_ACCESS_KEY: string;
  AWS_SESSION_TOKEN: string;
  // AWS_SECURITY_TOKEN is the legacy version of AWS_SESSION_TOKEN. It does seem to take precedence over AWS_SESSION_TOKEN. The okta-aws-cli sets both: https://github.com/okta/okta-aws-cli/blob/f1e09eab509e295a7e7b3002d14f2a96b8c60914/internal/output/envvar.go#L49L63
  AWS_SECURITY_TOKEN: string;
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

export type AwsLogin = AwsFederatedLogin | AwsIamLogin | AwsIdcLogin;

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
  resource: {
    account: string;
    accountId: string;
    arn: string;
    idcId: string;
    idcRegion: string;
    instanceId: string;
    name: string;
    userName: string;
  };
};

export type AwsSshGenerated = {
  resource: { name: string };
  linuxUserName: string;
  publicKey: string;
};

export type AwsSshPermissionSpec = PermissionSpec<
  "ssh",
  AwsSshPermission,
  AwsSshGenerated
>;

export type AwsSsh = CliPermissionSpec<AwsSshPermissionSpec, undefined>;

export type BaseAwsSshRequest = {
  linuxUserName: string;
  accountId: string;
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
