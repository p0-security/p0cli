/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

// Tracing initialization must happen before any other imports
// to ensure auto-instrumentation can monkey-patch imported libraries.
import { startTracing } from "./opentelemetry/instrumentation";
startTracing();

import { getCli } from "./commands";
import { loadConfig } from "./drivers/config";
import { print2 } from "./drivers/stdio";
import { trace } from "@opentelemetry/api";
import { isSea } from "node:sea";
import { noop } from "lodash";


// The tracer version number is the version of the manual P0 CLI instrumentation.
// It is not the version of the P0 CLI itself or the version of the OpenTelemetry library.
// Change this when the manual instrumentation adds / removes spans, attributes, etc.
const tracer = trace.getTracer("p0cli", "0.0.1");

export const main = async () => {
  await tracer.startActiveSpan("main", async (span) => {
    try {
      await run();
    } catch (error: any) {
      span.recordException(error);
      throw error;
    } finally {
      span.end();
    }
  });
};

const run = async () => {
  // Try to load the config early here to get the custom help/contact messages (if any)
  try {
    await loadConfig();
  } catch (error) {
    // The config file may not be present if the user has not yet logged in,
    //  or has deleted the config. In that case, ignore the error and continue.
    // It will use the default messages instead.
    if (typeof error !== 'string') {
      throw error;
    }
    if (!error.startsWith("Missing config file")) {
      throw error;
    }
  }

  const cli = await getCli();
  // We can suppress output here, as .fail() already print2 errors
  void (cli.parse() as any).catch(noop);
};

// Global error handlers, to avoid ungraceful crashes and to log errors that aren't caught elsewhere.
// We still exit with a non-zero code to indicate failure.
process.on("uncaughtException", (error) => {
  print2("Uncaught Exception: " + error.message);
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  print2("Unhandled Rejection: " + (reason instanceof Error ? reason.message : String(reason)));
  process.exit(1);
});

if (require.main === module || isSea()) {
  void main();
}
