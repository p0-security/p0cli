/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import type { OrgData } from "./org";

/** Helper functions to access auth fields */

/** Get provider type from org data */
export const getProviderType = (
  org: OrgData
): "cloudflare" | "okta" | "ping" | undefined => {
  return org.auth.type === "sso" && "providerType" in org.auth.provider
    ? org.auth.provider.providerType
    : undefined;
};

/** Get provider domain from org data */
export const getProviderDomain = (org: OrgData): string | undefined => {
  return org.auth.type === "sso" && "providerDomain" in org.auth.provider
    ? org.auth.provider.providerDomain
    : undefined;
};

/** Get client ID from org data */
export const getClientId = (org: OrgData): string | undefined => {
  return org.auth.type === "sso" && "clientId" in org.auth.provider
    ? org.auth.provider.clientId
    : undefined;
};

/** Get environment ID from org data */
export const getEnvironmentId = (org: OrgData): string | undefined => {
  return org.auth.type === "sso" && "environmentId" in org.auth.provider
    ? org.auth.provider.environmentId
    : undefined;
};

/** Get SSO provider from org data */
export const getSsoProvider = (org: OrgData): string | undefined => {
  return org.auth.type === "sso" ? org.auth.provider.ssoProvider : undefined;
};

/** Get provider ID from org data */
export const getProviderId = (org: OrgData): string | undefined => {
  return org.auth.type === "sso" && "providerId" in org.auth.provider
    ? org.auth.provider.providerId
    : undefined;
};

/** Check if org uses password authentication */
export const usePasswordAuth = (org: OrgData): boolean => {
  return org.auth.type === "password";
};

/** Get Microsoft primary domain from org data (for Azure/Microsoft providers) */
export const getMicrosoftPrimaryDomain = (org: OrgData): string | undefined => {
  return org.auth.type === "sso" &&
    "microsoftPrimaryDomain" in org.auth.provider
    ? org.auth.provider.microsoftPrimaryDomain
    : undefined;
};
