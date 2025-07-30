/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
type ApplicationConfig = {
  fs: {
    apiKey: string;
    authDomain: string;
    projectId: string;
    storageBucket: string;
    messagingSenderId: string;
    appId: string;
  };
  appUrl: string;
  environment: string;
  contactMessage: string;
  helpMessage: string;
};

export type GoogleApplicationConfig = ApplicationConfig & {
  google: {
    clientId: string;
    publicClientSecretForPkce: string;
  };
};

export type Config = ApplicationConfig | GoogleApplicationConfig;

type BaseOrgData = {
  clientId: string;
  providerId: string;
  providerDomain?: string;
  ssoProvider?:
    | "azure-oidc"
    | "google-oidc"
    | "google"
    | "microsoft"
    | "oidc-pkce"
    | "okta";
  usePassword?: boolean;
  tenantId: string;
  config: Config;
  authPassthrough?: boolean;
};

/** Publicly readable organization data */
export type RawOrgData = BaseOrgData &
  (
    | {
        providerType?: "okta";
      }
    | {
        providerType?: "ping";
        environmentId: string;
      }
  );

export type OrgData = RawOrgData & {
  slug: string;
};
