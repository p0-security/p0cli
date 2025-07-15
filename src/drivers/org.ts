import { RawOrgData } from "../types/org";
import { apiFetch } from "./api";
import { getTenantConfig } from "./config";

const tenantOrgUrl = (tenant: string) =>
  `${getTenantConfig().appUrl}/orgs/${tenant}`;

export const getOrgData = async (orgId: string) => {
  try {
    const orgData = await apiFetch<RawOrgData>(tenantOrgUrl(orgId), "GET");
    return orgData;
  } catch (e) {
    throw `Could not find organization. Please check the organization ID and try again.\n${e}`;
  }
};
