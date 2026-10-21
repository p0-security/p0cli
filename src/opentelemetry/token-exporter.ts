/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { ExportResult, ExportResultCode } from "@opentelemetry/core";
import { SpanExporter, ReadableSpan } from "@opentelemetry/sdk-trace-base";

/**
 * A SpanExporter that fetches the access token on every export.
 *
 * The OTLP exporter only accepts fixed headers, so a token set at login
 * expires while long-running commands keep exporting. This wrapper builds a
 * new delegate whenever `getToken` returns a different token.
 */
export class TokenRefreshingExporter implements SpanExporter {
  private token: string | undefined = undefined;
  private delegate: SpanExporter | undefined = undefined;

  constructor(
    private readonly getToken: () => Promise<string>,
    private readonly makeExporter: (token: string) => SpanExporter
  ) {}

  export(
    spans: ReadableSpan[],
    resultCallback: (result: ExportResult) => void
  ): void {
    this.getToken().then(
      (token) => {
        if (!this.delegate || token !== this.token) {
          // Shutting down lets in-flight exports finish with the old token
          void this.delegate?.shutdown().catch(() => {});
          this.token = token;
          this.delegate = this.makeExporter(token);
        }
        this.delegate.export(spans, resultCallback);
      },
      // Traces are best-effort telemetry; drop them if no token is available
      () => resultCallback({ code: ExportResultCode.FAILED })
    );
  }

  async forceFlush(): Promise<void> {
    await this.delegate?.forceFlush?.();
  }

  async shutdown(): Promise<void> {
    await this.delegate?.shutdown();
  }
}
