/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "./drivers/stdio";
import crypto from "node:crypto";
import https from "node:https";
import tls from "node:tls";

/**
 * Configure OpenSSL environment variables for bundled FIPS configuration
 */
const setupFipsEnvironment = () => {
  process.env.OPENSSL_CONF = "/usr/local/lib/p0/openssl.cnf";
  process.env.OPENSSL_MODULES = "/usr/local/lib/p0/ossl-modules";
};

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
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    print2(`Failed to enable FIPS mode: ${errorMessage}`);
    process.exit(1);
  }
};

/**
 * Create a FIPS-compliant HTTPS agent that forces TLS 1.2 and FIPS-approved algorithms
 */
const createFipsAgent = () => {
  return new https.Agent({
    minVersion: "TLSv1.2",
    maxVersion: "TLSv1.2",
    // Only FIPS-approved cipher suites
    ciphers: [
      "ECDHE-RSA-AES256-GCM-SHA384",
      "ECDHE-RSA-AES128-GCM-SHA256",
      "ECDHE-ECDSA-AES256-GCM-SHA384",
      "ECDHE-ECDSA-AES128-GCM-SHA256",
      "AES256-GCM-SHA384",
      "AES128-GCM-SHA256",
    ].join(":"),
    honorCipherOrder: true,
    // Only FIPS-approved elliptic curves (P-256, P-384)
    ecdhCurve: "prime256v1:secp384r1",
    // Force disable TLS 1.3 at the socket level
    secureOptions: crypto.constants.SSL_OP_NO_TLSv1_3,
  });
};

/**
 * Configure TLS for FIPS compliance by setting global HTTPS agent
 */
const configureFipsTls = () => {
  const fipsAgent = createFipsAgent();

  // Set the global HTTPS agent - this affects all HTTPS requests including fetch()
  https.globalAgent = fipsAgent;
};

/**
 * Initialize FIPS 140-2 compliance for Single Executable Applications
 * Sets up environment, enables FIPS mode, and configures compliant TLS settings
 */
export const initializeFips = () => {
  setupFipsEnvironment();
  enableFipsMode();
  configureFipsTls();
};
