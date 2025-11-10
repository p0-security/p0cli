/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import fs from "node:fs";
import os from "node:os";
import { getAsset, isSea } from "node:sea";

type VersionInfo = {
  name: string;
  version: string;
  build: { standalone: false } | { standalone: true; os: string; arch: string };
};

const loadCurrentVersion = (): VersionInfo => {
  try {
    if (isSea()) {
      // When building with the standalone CLI, we need to manually include the package.json as a
      // static asset in sea-config.json, as it is not included in the build by default.
      const packageJsonText = getAsset("package.json", "utf-8");
      const json = JSON.parse(packageJsonText);
      const { name, version, $build } = json;

      return {
        name,
        version,
        build: {
          standalone: true,
          os: $build?.os || os.platform(),
          arch: $build?.arch || os.arch(),
        },
      };
    }

    // Note that package.json is installed at <root>/package.json,
    // whereas this gets compiled to <root>/build/dist/version.js
    // in the build. We also need to adjust the path when running tests
    const packageJsonPath =
      process.env.NODE_ENV === "unit"
        ? `${__dirname}/../package.json`
        : `${__dirname}/../../package.json`;
    const { name, version } = JSON.parse(
      fs.readFileSync(packageJsonPath).toString("utf-8")
    );

    return {
      name,
      version,
      build: { standalone: false },
    };
  } catch {
    return {
      name: "@p0security/cli",
      version: "unknown",
      build: { standalone: false },
    };
  }
};

export const stringifyVersionInfo = (info: VersionInfo): string => {
  const { version, build } = info;
  if (build.standalone) {
    return `P0 Security CLI ${version} (built for ${build.os}/${build.arch})`;
  } else {
    return `P0 Security CLI ${version}`;
  }
};

// p0VersionInfo is a promise that resolves to the current version info
// The importer needs to await this promise to actually read the version number
// e.g. `const { name, version } = await p0VersionInfo;`
//
// This allows us to memoize the version info and avoid reading the
// package.json files multiple times
export const p0VersionInfo = loadCurrentVersion();
