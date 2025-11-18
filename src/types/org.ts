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
  skipVersionCheck?: string;
};

export type GoogleApplicationConfig = ApplicationConfig & {
  google: {
    clientId: string;
    publicClientSecretForPkce: string;
  };
};

export type Config = ApplicationConfig | GoogleApplicationConfig;

type AzureOidcProvider = {
  ssoProvider: "azure-oidc";
  microsoftPrimaryDomain: string;
};

type GoogleOidcProvider = {
  ssoProvider: "google-oidc";
};

type GoogleSsoProvider = {
  ssoProvider: "google";
};

type LegacyOktaSsoProvider = {
  ssoProvider: "okta";
  providerId: string;
};

type MicrosoftSsoProvider = {
  ssoProvider: "microsoft";
  microsoftPrimaryDomain: string;
};

type BaseOidcPkceProvider = {
  ssoProvider: "oidc-pkce";
  providerId: string;
  providerDomain: string;
  clientId: string;
};

type OktaOidcPkceProvider = BaseOidcPkceProvider & {
  providerType: "okta";
  authServerPath?: string;
};

type PingIdOidcPkceProvider = BaseOidcPkceProvider & {
  providerType: "ping";
  environmentId: string;
};

type CloudflareOidcPkceProvider = BaseOidcPkceProvider & {
  providerType: "cloudflare";
  clientSecret: string;
};

type OidcPkceProvider =
  | CloudflareOidcPkceProvider
  | OktaOidcPkceProvider
  | PingIdOidcPkceProvider;

type SsoProvider =
  | AzureOidcProvider
  | GoogleOidcProvider
  | GoogleSsoProvider
  | LegacyOktaSsoProvider
  | MicrosoftSsoProvider
  | OidcPkceProvider;

type OrgMagicLinkAuth = {
  type: "magic-link";
};

type OrgPasswordAuth = {
  type: "password";
};

type OrgSsoAuth = {
  type: "sso";
  provider: SsoProvider;
};

export type OrgAuth = OrgMagicLinkAuth | OrgPasswordAuth | OrgSsoAuth;

/** Legacy structure for backward compatibility */
type LegacyOrgData = {
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
  /** Swaps API auth to tokens from the ssoProvider, rather than firebase */
  useProviderToken?: boolean;
} & (
  | {
      providerType?: "okta";
    }
  | {
      providerType?: "ping";
      environmentId: string;
    }
) &
  SsoProvider;

export type NewOrgData = {
  tenantId: string;
  auth: OrgAuth;
  config: Config;
  /** Swaps API auth to tokens from the ssoProvider, rather than firebase */
  useProviderToken?: boolean;
};

/** Publicly readable organization data - supports both old and new structures */
export type RawOrgData = LegacyOrgData | NewOrgData;

export type OrgData = RawOrgData & {
  slug: string;
};
