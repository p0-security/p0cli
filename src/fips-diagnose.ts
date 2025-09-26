/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "./drivers/stdio";
import crypto from "node:crypto";
import os from "node:os";
import tls from "node:tls";
import { setGlobalDispatcher, Agent, fetch } from "undici";

const DIAGNOSTIC_URL = "https://fabian-joya.api.dev.p0.app/orgs/p0-fabian";

/**
 * Run comprehensive FIPS diagnostics to test TLS configuration and connectivity
 *
 * This function checks:
 * - Environment variables and Node.js versions
 * - FIPS mode status
 * - Available TLS ciphers with FIPS configuration
 * - Actual HTTPS connectivity using FIPS-compliant settings
 */
export const runFipsDiagnostics = async (): Promise<void> => {
  print2("=== Environment ===");
  print2(`Node: ${process.versions.node}`);
  print2(`OpenSSL: ${process.versions.openssl}`);

  try {
    print2(`crypto.getFips(): ${crypto.getFips()}`);
  } catch (error) {
    print2(`crypto.getFips(): Error - ${String(error)}`);
  }

  print2(`NODE_OPTIONS: ${process.env.NODE_OPTIONS || "(unset)"}`);
  print2(`OPENSSL_CONF: ${process.env.OPENSSL_CONF || "(unset)"}`);
  print2(`OPENSSL_MODULES: ${process.env.OPENSSL_MODULES || "(unset)"}`);
  print2(`Platform: ${os.platform()} ${os.release()}`);

  // Build a conservative, FIPS-safe TLS agent.
  // NOTE: Node/OpenSSL only uses `ciphers` for TLS<=1.2. TLS1.3 suites are not settable here.
  const fips12CipherList = [
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
  ].join(":");

  print2("\n=== TLS Cipher Validation ===");
  // Verify the cipher list actually resolves to something in this process
  try {
    const ctx = tls.createSecureContext({
      minVersion: "TLSv1.2",
      ciphers: fips12CipherList,
    });
    const enabled = ctx.context.getCiphers?.() || [];
    print2(`Enabled TLS<=1.2 ciphers count: ${enabled.length}`);
    if (enabled.length === 0) {
      print2(
        "!! No TLS<=1.2 ciphers enabled with current settings. Check NODE_OPTIONS/OPENSSL_CONF."
      );
    } else {
      print2(`Available ciphers: ${enabled.slice(0, 3).join(", ")}...`);
    }
  } catch (e: any) {
    print2(
      "!! Failed to create SecureContext with FIPS list: " + (e?.message || e)
    );
  }

  print2("\n=== FIPS Agent Test ===");
  setGlobalDispatcher(
    new Agent({
      connect: {
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.2",
        // IMPORTANT: This is for TLS1.2 and below only.
        ciphers: fips12CipherList,
        ecdhCurve: "prime256v1:secp384r1",
        secureOptions: crypto.constants.SSL_OP_NO_TLSv1_3,
      },
    })
  );

  print2("\n=== Fetch Connectivity Test ===");
  try {
    const res = await fetch(DIAGNOSTIC_URL, { method: "GET" });
    print2(`✅ Status: ${res.status}`);
    const body = await res.text();
    print2(`✅ Body (first 200 chars): ${body.slice(0, 200)}...`);
  } catch (e: any) {
    print2(
      `❌ Fetch error: ${e && (e.cause?.code || e.code)} ${e?.message || e}`
    );

    // Helpful hints for common failures
    if ((e?.message || "").includes("no ciphers")) {
      print2(
        "\n💡 HINT: You likely have an invalid/empty TLS cipher list. Avoid TLS_AES_* in --tls-cipher-list; use AES-GCM suites above."
      );
    }
    if ((e?.message || "").includes("X25519")) {
      print2(
        "\n💡 HINT: X25519 key exchange is not FIPS-approved. Ensure ecdhCurve is set to P-256/P-384 only."
      );
    }
  }
};
