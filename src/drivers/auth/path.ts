/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { P0_PATH } from "../../util";
import { compact } from "lodash";
import * as path from "path";

export const postfixPath = (fname: string) => {
  const parts = fname.split(".");
  return path.join(
    P0_PATH,
    process.env.P0_ORG
      ? compact([`${parts[0]}-${process.env.P0_ORG}`, parts[1]]).join(".")
      : fname
  );
};

export const getIdentityFilePath = () => postfixPath("identity.json");

export const getIdentityCachePath = () => postfixPath("cache");

export const getConfigFilePath = () => postfixPath("config.json");

export const getBootstrapOrgDataPath = (orgId: string): string => {
  const safeOrgId = path.basename(orgId);
  if (safeOrgId !== orgId) {
    throw new Error("Invalid organization");
  }

  const filename = `bootstrap-${safeOrgId}.json`;
  // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  const resolvedFilename = path.resolve(P0_PATH, filename);

  if (!resolvedFilename.startsWith(P0_PATH)) {
    throw new Error("Invalid organization");
  }

  return resolvedFilename;
};
