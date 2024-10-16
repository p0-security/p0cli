/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Config } from "../types/org";
import { P0_PATH } from "../util";
import { bootstrapConfig } from "./env";
import { print2 } from "./stdio";
import fs from "fs/promises";
import path from "path";

export const CONFIG_FILE_PATH = path.join(P0_PATH, "config.json");

export let tenantConfig = bootstrapConfig;

/**
 * Configures the CLI to use a tenant-specific configuration instead of the bootstrap configuration.
 * The tenant-specific config is also written to the local filesystem for future use.
 *
 * @param config the tenant-specific config to use
 */
export const saveTenantConfig = async (config: Config) => {
  tenantConfig = config;
  await writeConfigToFile(config);
};

/**
 * Configures the CLI to use a tenant-specific configuration, if present.
 *
 * Loads the tenant-specific config from the local filesystem, if present.
 * If not present, it will keep using the bootstrap config.
 */
export const loadTenantConfig = async () => {
  const config = await loadConfigFromFile();
  if (config) {
    tenantConfig = config;
  }
};

const loadConfigFromFile = async (): Promise<Config> => {
  print2(`Loading config from ${CONFIG_FILE_PATH}.`);
  const buffer = await fs.readFile(CONFIG_FILE_PATH);
  const config: Config = JSON.parse(buffer.toString());
  return config;
};

const writeConfigToFile = async (config: Config) => {
  print2(`Saving config to ${CONFIG_FILE_PATH}.`);
  const dir = path.dirname(CONFIG_FILE_PATH);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(CONFIG_FILE_PATH, JSON.stringify(config), { mode: "600" });
};
