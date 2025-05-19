/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { AuthorizeResponse, TokenResponse } from "../../types/oidc";
import { OrgData } from "../../types/org";
import { LoginPlugin, LoginPluginMethods } from "../login";
import { oidcLogin, oidcLoginSteps } from "../oidc/login";

const SCOPES = "openid email profile";

/** Logs in to PingOne via OIDC */
export const pingLogin: LoginPlugin = async (
  org: OrgData
): Promise<LoginPluginMethods> => {
  if (org.providerType !== "ping") {
    throw `Invalid provider type ${org.providerType} (expected "ping")`;
  }

  const urls = {
    deviceAuthorizationUrl: `https://${org.providerDomain}/${org.environmentId}/as/device_authorization`,
    tokenUrl: `https://${org.providerDomain}/${org.environmentId}/as/token`,
  };

  const loginSteps = oidcLoginSteps(org, SCOPES, () => urls);

  return {
    login: async () =>
      await oidcLogin<AuthorizeResponse, TokenResponse>(loginSteps),
    renewAccessToken: async (_refreshToken: string) =>
      Promise.resolve(undefined),
  };
};
