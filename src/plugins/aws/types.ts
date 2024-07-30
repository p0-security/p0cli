/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { CliPermissionSpec, PermissionSpec } from "../../types/request";
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

type AwsLogin = AwsFederatedLogin | AwsIamLogin | AwsIdcLogin;

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

export type AwsSshPermission = {
  spec: CommonSshPermissionSpec & {
    instanceId: string;
    accountId: string;
    region: string;
    type: "aws";
  };
  type: "session";
};

export type AwsSshGenerated = {
  name: string;
  ssh: {
    linuxUserName: string;
  };
};

export type AwsPermissionSpec = PermissionSpec<
  "ssh",
  AwsSshPermission,
  AwsSshGenerated
>;

export type AwsSsh = CliPermissionSpec<AwsPermissionSpec>;
