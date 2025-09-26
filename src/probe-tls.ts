/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "./drivers/stdio";
import { getFips } from "crypto";
import * as tls from "tls";

export interface TlsProbeInfo {
  node: string;
  openssl: string;
  fips: number;
  defaultMin: string;
  defaultMax: string;
  tls13Available: boolean;
  tls12ContextOk: boolean;
  tls13ContextOk: boolean;
  tls13Ciphers: string[];
  tls12Ciphers: string[];
  errorTLS12: string | null;
  errorTLS13: string | null;
}

export function probeTlsSupport(
  opts: { showLists?: boolean } = {}
): TlsProbeInfo {
  const { showLists = true } = opts;

  const info: TlsProbeInfo = {
    node: process.versions.node,
    openssl: process.versions.openssl,
    fips: typeof getFips === "function" ? getFips() : 0,
    defaultMin: (tls as any).DEFAULT_MIN_VERSION,
    defaultMax: (tls as any).DEFAULT_MAX_VERSION,
    tls13Available: false,
    tls12ContextOk: false,
    tls13ContextOk: false,
    tls13Ciphers: [],
    tls12Ciphers: [],
    errorTLS12: null,
    errorTLS13: null,
  };

  // Cipher names reported by Node (TLS 1.3 start with "TLS_")
  const all: string[] = tls.getCiphers();
  info.tls13Ciphers = all.filter((n) => n.startsWith("TLS_"));
  info.tls12Ciphers = all.filter((n) => !n.startsWith("TLS_"));
  info.tls13Available = info.tls13Ciphers.length > 0;

  // Try strict TLS 1.2 context
  try {
    tls.createSecureContext({ minVersion: "TLSv1.2", maxVersion: "TLSv1.2" });
    info.tls12ContextOk = true;
  } catch (e: unknown) {
    const err = e as { message?: string };
    info.tls12ContextOk = false;
    info.errorTLS12 = err?.message ?? String(e);
  }

  // Try strict TLS 1.3 context
  try {
    tls.createSecureContext({ minVersion: "TLSv1.3", maxVersion: "TLSv1.3" });
    info.tls13ContextOk = true;
  } catch (e: unknown) {
    const err = e as { message?: string };
    info.tls13ContextOk = false;
    info.errorTLS13 = err?.message ?? String(e);
  }

  if (showLists) {
    print2("=== Node/OpenSSL/FIPS ===");
    print2(
      JSON.stringify(
        {
          node: info.node,
          openssl: info.openssl,
          fips: info.fips,
          defaultMin: info.defaultMin,
          defaultMax: info.defaultMax,
          tls13Available: info.tls13Available,
          tls12ContextOk: info.tls12ContextOk,
          tls13ContextOk: info.tls13ContextOk,
          errorTLS12: info.errorTLS12,
          errorTLS13: info.errorTLS13,
        },
        null,
        2
      )
    );

    print2("\n=== TLS 1.3 ciphers ===");
    print2(info.tls13Ciphers.length ? info.tls13Ciphers.join(", ") : "(none)");

    print2("\n=== TLS ≤1.2 ciphers ===");
    print2(info.tls12Ciphers.length ? info.tls12Ciphers.join(", ") : "(none)");
  }

  return info;
}

// CommonJS-friendly "run if main"
if (
  typeof require !== "undefined" &&
  typeof module !== "undefined" &&
  require.main === module
) {
  probeTlsSupport();
}
