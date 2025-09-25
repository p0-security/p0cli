/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "./drivers/stdio";
import crypto from "node:crypto";
import https from "node:https";
import { setGlobalDispatcher, Agent, buildConnector } from "undici";

/**
 * FIPS-approved TLS configuration shared by both HTTPS and Undici agents
 */
const FIPS_TLS_CONFIG = {
  minVersion: "TLSv1.2" as const,
  maxVersion: "TLSv1.2" as const,
  ciphers: [
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
  ].join(":"),
  honorCipherOrder: true,
  ecdhCurve: "prime256v1:secp384r1",
  secureOptions: crypto.constants.SSL_OP_NO_TLSv1_3,
} as const;

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
 * Configure TLS for FIPS compliance using Undici dispatcher and HTTPS agent
 */
const configureFipsTls = () => {
  // Create FIPS-compliant Undici connector and agent for fetch() calls
  const connector = buildConnector({
    // @ts-expect-error - `tls` is valid at runtime in Undici 6.21.x
    tls: FIPS_TLS_CONFIG,
  });
  const undiciAgent = new Agent({ connect: connector });
  setGlobalDispatcher(undiciAgent);

  // Create FIPS-compliant HTTPS agent for traditional https.request() calls
  const httpsAgent = new https.Agent(FIPS_TLS_CONFIG);
  https.globalAgent = httpsAgent;
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
