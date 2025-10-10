/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { shouldSkipCheckVersion } from "../drivers/config";
import { print2 } from "../drivers/stdio";
import { P0_PATH, exec, getOperatingSystem, timeout } from "../util";
import { p0VersionInfo } from "../version";
import fs from "node:fs/promises";
import path from "node:path";
import { isSea } from "node:sea";
import semver from "semver";
import yargs from "yargs";

const LATEST_VERSION_FILE = "last-version-check";

// We don't want to add any significant overhead to p0 commands with the version check,
// so just give up if it takes too long.
const VERSION_CHECK_TIMEOUT_MILLIS = 2e3;

const VERSION_CHECK_INTERVAL_MILLIS = 86400e3; // 1 day

type NpmPackageOutput = {
  "dist-tags": {
    latest: string;
  };
};

/** Checks if there is a new version of the CLI
 *
 * If there is, prints an upgrade banner.
 *
 * If there is no new version, or if version lookup errors, just pass silently.
 */
export const checkVersion = async (yargs: yargs.ArgumentsCamelCase) => {
  const isDebug = Boolean(yargs["debug"]);
  if (shouldSkipCheckVersion()) {
    if (isDebug) {
      print2("Skipping version check");
    }
    return;
  }
  try {
    const latestFile = path.join(P0_PATH, LATEST_VERSION_FILE);
    try {
      const stat = await fs.stat(latestFile);
      const msSinceLastCheck = Date.now() - stat.mtime.getTime();
      if (msSinceLastCheck <= VERSION_CHECK_INTERVAL_MILLIS) {
        if (isDebug) {
          print2(
            "Skipping version check; last checked " +
              Math.round(msSinceLastCheck / (1000 * 60)) +
              " minutes ago."
          );
        }
        return;
      }
    } catch (error: any) {
      if (error.code !== "ENOENT") throw error;
    }

    // Write the version-check file first to avoid retrying errors
    // Ensure that the directory exists beforehand
    const dirname = path.dirname(latestFile);
    await fs.mkdir(dirname, { recursive: true });
    await fs.writeFile(latestFile, "");

    const { name, version: current } = p0VersionInfo;

    if (isDebug) {
      print2("Checking that your CLI is up to date with the latest version...");
    }

    // On Windows, the main npm file is not an .exe (binary executable) file,
    // so when calling spawn, it cannot be located except via cmd.exe
    const isWindows = getOperatingSystem() === "win";
    const npmCmd = isWindows ? "cmd.exe" : "npm";
    const commonNpmArgs = ["view", name, "--json"];
    const npmArgs = isWindows
      ? ["/d", "/s", "/c", "npm", ...commonNpmArgs]
      : commonNpmArgs;

    const processResult = await timeout(
      exec(npmCmd, npmArgs, { check: true }),
      VERSION_CHECK_TIMEOUT_MILLIS
    );
    const npmPackage: NpmPackageOutput = JSON.parse(processResult.stdout);
    const { latest } = npmPackage["dist-tags"];

    if (isDebug) {
      print2("Package info successfully retrieved.");
      print2("Latest version: " + latest.padStart(15));
      print2("Your version:   " + current.padStart(15));
    }

    if (semver.lt(current, latest)) {
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
    } else if (isDebug) {
      print2("Your version of the CLI is up to date.");
    }
  } catch (error: any) {
    if (isDebug) {
      print2(`Version check failed: ${error.message}`);
      print2("Ignoring this error and continuing...");
    }

    // Silently pass errors
    // TODO: log to ~/.p0
  }
};
