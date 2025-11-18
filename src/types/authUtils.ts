/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import type { NewOrgData, OrgData } from "./org";

/** Helper functions to access auth fields with backward compatibility */

/** Check if org data uses the new auth structure */
export const hasNewAuthStructure = (
  org: OrgData
): org is NewOrgData & { slug: string } => {
  return "auth" in org && org.auth !== undefined;
};

/** Get provider type from org data */
export const getProviderType = (
  org: OrgData
): "cloudflare" | "okta" | "ping" | undefined => {
  if (hasNewAuthStructure(org)) {
    return org.auth.type === "sso" && "providerType" in org.auth.provider
      ? org.auth.provider.providerType
      : undefined;
  }
  return ("providerType" in org && org.providerType) || undefined;
};

/** Get provider domain from org data */
export const getProviderDomain = (org: OrgData): string | undefined => {
  if (hasNewAuthStructure(org)) {
    return org.auth.type === "sso" && "providerDomain" in org.auth.provider
      ? org.auth.provider.providerDomain
      : undefined;
  }
  return ("providerDomain" in org && org.providerDomain) || undefined;
};

/** Get client ID from org data */
export const getClientId = (org: OrgData): string | undefined => {
  if (hasNewAuthStructure(org)) {
    return org.auth.type === "sso" && "clientId" in org.auth.provider
      ? org.auth.provider.clientId
      : undefined;
  }
  return ("clientId" in org && org.clientId) || undefined;
};

/** Get environment ID from org data */
export const getEnvironmentId = (org: OrgData): string | undefined => {
  if (hasNewAuthStructure(org)) {
    return org.auth.type === "sso" && "environmentId" in org.auth.provider
      ? org.auth.provider.environmentId
      : undefined;
  }
  return ("environmentId" in org && org.environmentId) || undefined;
};

/** Get SSO provider from org data */
export const getSsoProvider = (org: OrgData): string | undefined => {
  if (hasNewAuthStructure(org)) {
    return org.auth.type === "sso" ? org.auth.provider.ssoProvider : undefined;
  }
  return ("ssoProvider" in org && org.ssoProvider) || undefined;
};

/** Get provider ID from org data */
export const getProviderId = (org: OrgData): string | undefined => {
  if (hasNewAuthStructure(org)) {
    return org.auth.type === "sso" && "providerId" in org.auth.provider
      ? org.auth.provider.providerId
      : undefined;
  }
  return ("providerId" in org && org.providerId) || undefined;
};

/** Check if org uses password authentication */
export const usePasswordAuth = (org: OrgData): boolean => {
  if (hasNewAuthStructure(org)) {
    return org.auth.type === "password";
  }
  return ("usePassword" in org && org.usePassword) || false;
};
