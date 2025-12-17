/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { BufferedExporterBase } from "./buffered-exporter-base";
import { ExportResult, ExportResultCode } from "@opentelemetry/core";
import {
  PushMetricExporter,
  ResourceMetrics,
} from "@opentelemetry/sdk-metrics";

/**
 * A MetricExporter that buffers metrics in memory until a delegate exporter is available.
 *
 * This is useful when metrics are created before authentication
 * and the actual exporter (e.g., OTLP exporter with access token)
 * can only be initialized after login.
 *
 * Metrics exported before the delegate is set are stored in an internal buffer.
 * Once the delegate exporter is injected via `setDelegateAndExport()`,
 * all buffered metrics are flushed to the delegate. Future metrics are exported directly.
 *
 * @implements {import('@opentelemetry/sdk-metrics').PushMetricExporter}
 */
export class BufferedMetricExporter
  extends BufferedExporterBase<PushMetricExporter>
  implements PushMetricExporter
{
  private buffer: ResourceMetrics[] = [];

  export(
    metrics: ResourceMetrics,
    resultCallback: (result: ExportResult) => void
  ): void {
    if (this.checkShutdown()) {
      resultCallback({ code: ExportResultCode.FAILED });
      return;
    }

    if (this.delegate) {
      try {
        this.delegate.export(metrics, resultCallback);
      } catch (error) {
        // Silently ignore export errors - metrics are best-effort telemetry
        resultCallback({ code: ExportResultCode.FAILED });
      }
    } else {
      this.buffer.push(metrics);
      resultCallback({ code: ExportResultCode.SUCCESS });
    }
  }

  setDelegateAndExport(exporter: PushMetricExporter) {
    if (this.checkShutdown()) return;

    this.setDelegate(exporter);

    if (this.buffer.length > 0) {
      const toFlush = this.buffer.splice(0);
      for (const metrics of toFlush) {
        try {
          this.delegate!.export(metrics, (result: ExportResult) => {
            if (result.code === ExportResultCode.FAILED) {
              // Silently ignore export failures
            }
          });
        } catch (error) {
          // Silently ignore export errors
        }
      }
    }
  }
}
