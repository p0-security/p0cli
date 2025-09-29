/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "./drivers/stdio";
import { runFipsDiagnostics } from "./fips-diagnose";
import crypto from "node:crypto";

/**
 * Enable FIPS mode and verify it's working
 */
const enableFipsMode = () => {
  try {
    crypto.setFips(true);
    const fipsEnabled = crypto.getFips();
    if (!fipsEnabled) {
      print2(`Failed to enable FIPS mode`);
      process.exit(1);
    }
    print2(`FIPS mode enabled: ${fipsEnabled ? 1 : 0}`);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    print2(`Failed to enable FIPS mode: ${errorMessage}`);
    process.exit(1);
  }
};

/**
 * Initialize FIPS 140-2 compliance for Single Executable Applications
 * Sets up environment, enables FIPS mode, and configures compliant TLS settings
 */
export const initializeFips = async () => {
  enableFipsMode();
  await runFipsDiagnostics();
};
