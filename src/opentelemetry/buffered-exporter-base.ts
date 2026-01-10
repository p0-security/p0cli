/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

/**
 * Base class for exporters that buffer data in memory until a delegate exporter is available.
 *
 * This is useful when telemetry data is created before authentication
 * and the actual exporter (e.g., OTLP exporter with access token)
 * can only be initialized after login.
 *
 * Data exported before the delegate is set is stored in an internal buffer.
 * Once the delegate exporter is injected via `setDelegateAndExport()`,
 * all buffered data is flushed to the delegate. Future data is exported directly.
 */
export abstract class BufferedExporterBase<
  TExporter extends {
    forceFlush?: () => Promise<void>;
    shutdown?: () => Promise<void>;
  },
> {
  protected delegate: TExporter | undefined = undefined;
  protected isShutdown = false;

  async forceFlush(): Promise<void> {
    if (this.delegate) {
      try {
        await this.delegate.forceFlush?.();
      } catch (error) {
        // Silently ignore flush errors
      }
    }
    // No-op if buffering
  }

  async shutdown(): Promise<void> {
    this.isShutdown = true;
    if (this.delegate) {
      try {
        await this.delegate.shutdown?.();
      } catch (error) {
        // Silently ignore shutdown errors
      }
    }
  }

  protected checkShutdown(): boolean {
    return this.isShutdown;
  }

  protected setDelegate(exporter: TExporter): void {
    this.delegate = exporter;
  }
}
