/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { P0_PATH } from "../../util";
import * as fs from "fs/promises";
import path from "path";

// Clean up SSH config files older than this threshold (in milliseconds)
// Default: 24 hours
const STALE_CONFIG_THRESHOLD_MS = 24 * 60 * 60 * 1000;

/**
 * Cleanup stale SSH config files that were not properly deleted
 *
 * This function removes config files in the ssh/configs directory that are older
 * than STALE_CONFIG_THRESHOLD_MS. These files should normally be cleaned up
 * by ssh-proxy, but may be left behind if:
 * - The SSH connection was never established
 * - ssh-proxy crashed before cleanup
 * - The user cancelled the connection
 *
 * @param debug - Whether to print debug information
 */
export const cleanupStaleSshConfigs = async (debug?: boolean) => {
  try {
    const configsDir = path.join(P0_PATH, "ssh", "configs");

    // Check if the directory exists
    try {
      await fs.access(configsDir);
    } catch {
      // Directory doesn't exist, nothing to clean up
      return;
    }

    const files = await fs.readdir(configsDir);
    const configFiles = files.filter((file) => file.endsWith(".config"));

    const now = Date.now();
    let cleanedCount = 0;

    for (const file of configFiles) {
      const filePath = path.join(configsDir, file);

      try {
        const stats = await fs.stat(filePath);
        const ageMs = now - stats.mtimeMs;

        if (ageMs > STALE_CONFIG_THRESHOLD_MS) {
          await fs.rm(filePath);
          cleanedCount++;
          if (debug) {
            const ageHours = ageMs / 1000 / 60 / 60;
            print2(
              `Cleaned up stale SSH config file: ${file} (age: ${ageHours.toFixed(1)} hours)`
            );
          }
        }
      } catch (err) {
        if (debug) {
          print2(`Warning: Failed to process ${file}: ${String(err)}`);
        }
      }
    }

    if (debug && cleanedCount > 0) {
      print2(`Cleaned up ${cleanedCount} stale SSH config file(s)`);
    }
  } catch (err) {
    if (debug) {
      print2(`Warning: Failed to cleanup stale SSH configs: ${String(err)}`);
    }
  }
};
