/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { TokenResponse } from "../../types/oidc";
import { OrgData } from "../../types/org";
import { oidcLogin, oidcLoginSteps } from "../oidc/login";

const AZURE_SCOPE = "openid profile email offline_access";

const azureUrls = (org: OrgData) => {
  if (!org.providerDomain) {
    throw "Azure login requires a configured provider domain.";
  }
  
  const baseUrl = `https://login.microsoftonline.com/${org.providerDomain}/oauth2/v2.0`;
  return {
    deviceAuthorizationUrl: `${baseUrl}/devicecode`,
    tokenUrl: `${baseUrl}/token`,
  };
};

export const azureLogin = async (org: OrgData): Promise<TokenResponse> => {
  const steps = oidcLoginSteps(org, AZURE_SCOPE, () => azureUrls(org));
  return await oidcLogin<any, TokenResponse>(steps);
};