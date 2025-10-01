/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../drivers/stdio";
import { P0_PATH, exec, timeout } from "../util";
import { p0VersionInfo } from "../version";
import fs from "node:fs/promises";
import path from "node:path";
import { isSea } from "node:sea";
import semver from "semver";
import yargs from "yargs";

const LATEST_VERSION_FILE = "last-version-check";

// We don't want to add any significant overhead to p0 commands with the version check,
// so just give up if it takes too long.
const VERSION_CHECK_TIMEOUT_MILLIS = 1e3;

const VERSION_CHECK_INTERVAL_MILLIS = 86400e3; // 1 day

/** Checks if there is a new version of the CLI
 *
 * If there is, prints an upgrade banner.
 *
 * If there is no new version, or if version lookup errors, just pass silently.
 */
export const checkVersion = async (_yargs: yargs.ArgumentsCamelCase) => {
  try {
    const latestFile = path.join(P0_PATH, LATEST_VERSION_FILE);
    try {
      const stat = await fs.stat(latestFile);
      if (Date.now() - stat.mtime.getTime() <= VERSION_CHECK_INTERVAL_MILLIS)
        return;
    } catch (error: any) {
      if (error.code !== "ENOENT") throw error;
    }

    // Write the version-check file first to avoid retrying errors
    await fs.writeFile(latestFile, "");

    const { name, version } = p0VersionInfo;

    const npmResult = exec("npm", ["view", name, "--json"], { check: true });
    const npmPackage = await timeout(npmResult, VERSION_CHECK_TIMEOUT_MILLIS);
    const {
      "dist-tags": { latest },
    } = JSON.parse(npmPackage.stdout);

    if (semver.lt(version, latest)) {
      if (isSea()) {
        print2(
          `╔═══════════════════════════════════════════════╗
║ A new version is available                    ║
║                                               ║
║ To install, download the latest version       ║
║ from the GitHub releases page:                ║
║ https://github.com/p0-security/p0cli/releases ║
╚═══════════════════════════════════════════════╝
`
        );
      } else {
        print2(
          `╔══════════════════════════════════════╗
║ A new version is available           ║
║                                      ║
║ To install, run                      ║
║   npm -g update ${name.padEnd(20)} ║
╚══════════════════════════════════════╝
`
        );
      }
    }
  } catch (error: any) {
    // Silently pass errors
    // TODO: log to ~/.p0
  }
};
