/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { p0VersionInfo } from "../version";
import { BufferedSpanExporter } from "./buffered-exporter";
import { BufferedMetricExporter } from "./buffered-metric-exporter";
import { metrics } from "@opentelemetry/api";
import { OTLPMetricExporter } from "@opentelemetry/exporter-metrics-otlp-http";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { DnsInstrumentation } from "@opentelemetry/instrumentation-dns";
import { NetInstrumentation } from "@opentelemetry/instrumentation-net";
import { UndiciInstrumentation } from "@opentelemetry/instrumentation-undici";
import { resourceFromAttributes } from "@opentelemetry/resources";
import {
  MeterProvider,
  PeriodicExportingMetricReader,
} from "@opentelemetry/sdk-metrics";
import { NodeSDK } from "@opentelemetry/sdk-node";
import {
  ATTR_SERVICE_NAME,
  ATTR_SERVICE_VERSION,
} from "@opentelemetry/semantic-conventions";

export const bufferedExporter = new BufferedSpanExporter();
export const bufferedMetricExporter = new BufferedMetricExporter();

const resource = resourceFromAttributes({
  [ATTR_SERVICE_NAME]: p0VersionInfo.name,
  [ATTR_SERVICE_VERSION]: p0VersionInfo.version,
});

const metricReader = new PeriodicExportingMetricReader({
  exporter: bufferedMetricExporter,
  exportIntervalMillis: 30000, // Export every 30 seconds
});

const meterProvider = new MeterProvider({
  resource,
  readers: [metricReader],
});

metrics.setGlobalMeterProvider(meterProvider);

const sdk = new NodeSDK({
  resource,
  traceExporter: bufferedExporter,
  instrumentations: [
    new DnsInstrumentation(),
    new NetInstrumentation(),
    new UndiciInstrumentation(),
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

export const setMetricsExporterAfterLogin = async (
  url: string,
  token: string
) => {
  const realMetricExporter = new OTLPMetricExporter({
    url,
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  bufferedMetricExporter.setDelegateAndExport(realMetricExporter);
};

export const getMeter = () => {
  return metrics.getMeter("p0cli", "0.0.1");
};

export const startTracing = () => {
  sdk.start();
};

const shutdownSdk = () => {
  Promise.all([
    metricReader.forceFlush(),
    sdk.shutdown(),
    meterProvider.shutdown(),
  ]).finally(() => {
    process.exit();
  });
};

// These handlers are necessary to ensure spans are flushed when the CLI exits.
process.on("SIGINT", shutdownSdk);
process.on("SIGTERM", shutdownSdk);
process.on("beforeExit", shutdownSdk);
process.on("uncaughtException", shutdownSdk);
