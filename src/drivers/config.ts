/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Config, RawOrgData } from "../types/org";
import { P0_PATH } from "../util";
import { bootstrapConfig } from "./env";
import { bootstrapDoc } from "./firestore";
import { print2 } from "./stdio";
import { getDoc } from "firebase/firestore";
import fs from "fs/promises";
import path from "path";

export const CONFIG_FILE_PATH = path.join(P0_PATH, "config.json");

let tenantConfig: Config;

export const getTenantConfig = () => tenantConfig;

/** Use only if the organization is configured with Google login to P0 */
export const getGoogleTenantConfig = () => {
  if ("google" in tenantConfig) {
    return tenantConfig;
  }
  throw "Login failed!\nThis organization is configured to use Google login but the required OAuth client parameters are missing.\nPlease contact support@p0.dev to properly configure your organization login.";
};

export const saveConfig = async (orgId: string) => {
  const orgDoc = await getDoc<RawOrgData, object>(
    bootstrapDoc(`orgs/${orgId}`)
  );
  const orgData = orgDoc.data();

  if (!orgData) throw "Could not find organization";

  const config = orgData.config ?? bootstrapConfig;

  print2(`Saving config to ${CONFIG_FILE_PATH}.`);

  const dir = path.dirname(CONFIG_FILE_PATH);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(CONFIG_FILE_PATH, JSON.stringify(config), { mode: "600" });

  tenantConfig = config;
};

export const loadConfig = async () => {
  const buffer = await fs.readFile(CONFIG_FILE_PATH);
  tenantConfig = JSON.parse(buffer.toString());
  return tenantConfig;
};
