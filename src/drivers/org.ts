/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { RawOrgData } from "../types/org";
import { fetchOrgData } from "./api";
import { print2 } from "./stdio";

export const getOrgData = async (orgId: string) => {
  try {
    return await fetchOrgData<RawOrgData>(orgId);
  } catch (e: any) {
    if (typeof e === "string" && e.startsWith("Network error:")) {
      throw e;
    }
    if (typeof e === "string" && e.startsWith("Not found")) {
      throw "Could not find organization";
    }
    throw e;
  }
};
