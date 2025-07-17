/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { ExportResult, ExportResultCode } from "@opentelemetry/core";
import { SpanExporter, ReadableSpan } from "@opentelemetry/sdk-trace-base";

/**
 * A SpanExporter that buffers spans in memory until a delegate exporter is available.
 *
 * This is useful when trace spans are created before authentication
 * and the actual exporter (e.g., OTLP exporter with access token)
 * can only be initialized after login.
 *
 * Spans exported before the delegate is set are stored in an internal buffer.
 * Once the delegate exporter is injected via `setDelegateAndExport()`,
 * all buffered spans are flushed to the delegate. Future spans are exported directly.
 *
 * @implements {import('@opentelemetry/sdk-trace-base').SpanExporter}
 */
export class BufferedSpanExporter implements SpanExporter {
  private buffer: ReadableSpan[] = [];
  private delegate: SpanExporter | undefined = undefined;
  private isShutdown = false;

  export(
    spans: ReadableSpan[],
    resultCallback: (result: ExportResult) => void
  ): void {
    if (this.isShutdown) {
      resultCallback({ code: ExportResultCode.FAILED });
      return;
    }

    if (this.delegate) {
      this.delegate.export(spans, resultCallback);
    } else {
      this.buffer.push(...spans);
      resultCallback({ code: ExportResultCode.SUCCESS });
    }
  }

  async forceFlush(): Promise<void> {
    if (this.delegate) {
      return this.delegate.forceFlush?.();
    }
    // No-op if buffering
  }

  async shutdown(): Promise<void> {
    this.isShutdown = true;
    if (this.delegate) {
      return this.delegate.shutdown();
    }
  }

  setDelegateAndExport(exporter: SpanExporter) {
    if (this.isShutdown) return;

    this.delegate = exporter;

    if (this.buffer.length > 0) {
      const toFlush = this.buffer.splice(0);
      this.delegate.export(toFlush, () => {});
    }
  }
}
