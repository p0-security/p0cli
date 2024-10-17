/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Config } from "../types/org";
import { P0_PATH } from "../util";
import { print2 } from "./stdio";
import fs from "fs/promises";
import path from "path";

export const CONFIG_FILE_PATH = path.join(P0_PATH, "config.json");

export let tenantConfig: Config;

export async function saveConfig(config: Config) {
  print2(`Saving config to ${CONFIG_FILE_PATH}.`);
  const dir = path.dirname(CONFIG_FILE_PATH);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(CONFIG_FILE_PATH, JSON.stringify(config), { mode: "600" });
}

export async function loadConfig() {
  const buffer = await fs.readFile(CONFIG_FILE_PATH);
  tenantConfig = JSON.parse(buffer.toString());
}
