/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { P0_PATH } from "../../util";
import * as path from "path";

export const getIdentityFilePath = () =>
  process.env.P0_ORG
    ? path.join(P0_PATH, `identity-${process.env.P0_ORG}.json`)
    : path.join(P0_PATH, "identity.json");

export const getIdentityCachePath = () =>
  process.env.P0_ORG
    ? path.join(P0_PATH, `cache-${process.env.P0_ORG}`)
    : path.join(P0_PATH, "cache");

export const getConfigFilePath = () =>
  process.env.P0_ORG
    ? path.join(P0_PATH, `config.json-${process.env.P0_ORG}`)
    : path.join(P0_PATH, "config.json");

export const getBootstrapOrgDataPath = (orgId: string) =>
  path.join(P0_PATH, `bootstrap-${orgId}.json`);
