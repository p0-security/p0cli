/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import fs from "node:fs/promises";
import { getAssetAsBlob, isSea } from "node:sea";

const loadCurrentVersion = async (): Promise<{
  name: string;
  version: string;
}> => {
  if (isSea()) {
    const packageJsonBytes = getAssetAsBlob("package.json");
    const json = JSON.parse(await packageJsonBytes.text());
    const { name, version } = json;
    return { name, version };
  }

  // Note that package.json is installed at <root>/package.json,
  // whereas this gets compiled to <root>/build/dist/version.js
  // in the build. We also need to adjust the path when running tests
  const packageJsonPath = process.env.TS_JEST
    ? `${__dirname}/../package.json`
    : `${__dirname}/../../package.json`;
  const { name, version } = JSON.parse(
    (await fs.readFile(packageJsonPath)).toString("utf-8")
  );

  return { name, version };
};

export const P0_VERSION_INFO = loadCurrentVersion();
