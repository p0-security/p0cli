/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Config } from "../types/org";
import { getConfigFilePath } from "./auth/path";
import { bootstrapConfig } from "./env";
import { getOrgData } from "./org";
import { print2 } from "./stdio";
import fs from "fs/promises";
import path from "path";

let tenantConfig: Config;

export const getTenantConfig = () => tenantConfig;

export const getContactMessage = () =>
  tenantConfig?.contactMessage ?? bootstrapConfig.contactMessage;

export const getHelpMessage = () =>
  tenantConfig?.helpMessage ?? bootstrapConfig.helpMessage;

/** Use only if the organization is configured with Google login to P0 */
export const getGoogleTenantConfig = () => {
  if ("google" in tenantConfig) {
    return tenantConfig;
  }
  throw `Login failed!\nThis organization is configured to use Google login but the required OAuth client parameters are missing.\n${getContactMessage()}`;
};

export const saveConfig = async (orgId: string) => {
  const orgData = await getOrgData(orgId);

  const config = orgData.config ?? bootstrapConfig;

  const configFilePath = getConfigFilePath();

  print2(`Saving config to ${configFilePath}.`);

  const dir = path.dirname(configFilePath);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(configFilePath, JSON.stringify(config), { mode: "600" });

  tenantConfig = config;
};

export const loadConfig = async () => {
  const buffer = await fs.readFile(getConfigFilePath());
  tenantConfig = JSON.parse(buffer.toString());
  return tenantConfig;
};
