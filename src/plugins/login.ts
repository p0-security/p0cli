/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { TokenResponse } from "../types/oidc";
import { OrgData } from "../types/org";
import { emailPasswordLogin } from "./email/login";
import { googleLogin } from "./google/login";
import { oktaLogin } from "./okta/login";
import { pingLogin } from "./ping/login";

const loginPlugins = [
  "google",
  "okta",
  "ping",
  "oidc-pkce",
  "microsoft",
  "azure-oidc",
  "google-oidc",
  "aws-oidc",
] as const;

export type LoginPluginType = (typeof loginPlugins)[number];

export type LoginPluginMethods = {
  login: (org: OrgData) => Promise<TokenResponse>;
  renewAccessToken: (
    refreshToken: string
  ) => Promise<TokenResponse | undefined>;
};

export type LoginPlugin = (org: OrgData) => Promise<LoginPluginMethods>;

export const loginPluginMap: Record<string, LoginPlugin> = {
  google: googleLogin,
  okta: oktaLogin,
  ping: pingLogin,
  "google-oidc": googleLogin,
  password: emailPasswordLogin,
  "oidc-pkce": async (org: OrgData) =>
    await loginPluginMap[org.providerType!]!(org),
};
