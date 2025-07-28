import { RawOrgData } from "../types/org";
import { fetchOrgData } from "./api";
import { print2 } from "./stdio";

export const getOrgData = async (orgId: string) => {
  try {
    return await fetchOrgData<RawOrgData>(orgId);
  } catch (e) {
    print2(
      "Could not find organization. Please check the organization ID and try again."
    );
    throw "Could not find organization";
  }
};
