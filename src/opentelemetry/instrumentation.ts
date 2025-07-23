/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { p0VersionInfo } from "../version";
import { BufferedSpanExporter } from "./buffered-exporter";
import { getNodeAutoInstrumentations } from "@opentelemetry/auto-instrumentations-node";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { NodeSDK } from "@opentelemetry/sdk-node";
import {
  ATTR_SERVICE_NAME,
  ATTR_SERVICE_VERSION,
} from "@opentelemetry/semantic-conventions";

export const bufferedExporter = new BufferedSpanExporter();

const sdk = new NodeSDK({
  resource: resourceFromAttributes({
    [ATTR_SERVICE_NAME]: p0VersionInfo.name,
    [ATTR_SERVICE_VERSION]: p0VersionInfo.version,
  }),
  traceExporter: bufferedExporter,
  instrumentations: [
    // Disable instrumentations to decrease span volume
    getNodeAutoInstrumentations({
      "@opentelemetry/instrumentation-net": {
        enabled: false,
      },
      "@opentelemetry/instrumentation-dns": {
        enabled: false,
      },
      // Spans such as `grpc.google.firestore.v1.Firestore/Listen` are part of long running background tasks
      "@opentelemetry/instrumentation-grpc": {
        ignoreGrpcMethods: ["Listen"],
      },
    }),
  ],
});

export const setExporterAfterLogin = async (url: string, token: string) => {
  const realExporter = new OTLPTraceExporter({
    url,
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  bufferedExporter.setDelegateAndExport(realExporter);
};

export const startTracing = () => {
  sdk.start();
};

const shutdownSdk = () => {
  void sdk.shutdown().finally(() => {
    process.exit();
  });
};

// These handlers are necessary to ensure spans are flushed when the CLI exits.
process.on("SIGINT", shutdownSdk);
process.on("SIGTERM", shutdownSdk);
process.on("beforeExit", shutdownSdk);
process.on("uncaughtException", shutdownSdk);
