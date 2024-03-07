/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
export type AwsCredentials = {
  AWS_ACCESS_KEY_ID: string;
  AWS_SECRET_ACCESS_KEY: string;
  AWS_SESSION_TOKEN: string;
};

export type AwsOktaSamlUidLocation = {
  id: "okta_saml_sso";
  samlProviderName: string;
  appId: string;
};

type AwsUidLocation =
  | AwsOktaSamlUidLocation
  | { id: "idc"; parentId: string }
  | { id: "user_tag"; tagName: string }
  | { id: "username" };

export type AwsItemConfig = {
  account: {
    id: string;
    description?: string;
  };
  state: string;
  uidLocation?: AwsUidLocation;
};

export type AwsConfig = {
  workflows?: {
    items: AwsItemConfig[];
  };
};

// -- Specific AWS permission types

export type AwsSsh = {
  permission: {
    spec: {
      resource: {
        arn: string;
        type: "arn";
      };
    };
    type: "session";
  };
  generated: {
    documentName: string;
  };
};
