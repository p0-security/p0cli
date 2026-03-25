/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  getClientId,
  getProviderDomain,
  getProviderType,
} from "../../types/authUtils";
import { AuthorizeResponse, TokenResponse } from "../../types/oidc";
import { OrgData } from "../../types/org";
import { oidcLogin, oidcLoginSteps } from "../oidc/login";

/** Logs in to Duo via OIDC */
export const duoLogin = async (org: OrgData) =>
  oidcLogin<AuthorizeResponse, TokenResponse>(
    oidcLoginSteps(org, "openid email profile", () => {
      const providerType = getProviderType(org);
      const providerDomain = getProviderDomain(org);
      const clientId = getClientId(org);

      if (providerType !== "duo" || !providerDomain || !clientId) {
        throw `Invalid provider ${providerType} (expected duo OIDC provider)`;
      }
      return {
        deviceAuthorizationUrl: `https://${providerDomain}/oidc/${clientId}/device/authorization`,
        tokenUrl: `https://${providerDomain}/oidc/${clientId}/token`,
      };
    })
  );
