/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { TokenRefreshingExporter } from "../token-exporter";
import { ExportResult, ExportResultCode } from "@opentelemetry/core";
import { ReadableSpan, SpanExporter } from "@opentelemetry/sdk-trace-base";
import { describe, expect, it, vi } from "vitest";

const spans = [{ name: "span" } as unknown as ReadableSpan];

const fakeExporter = () => ({
  export: vi.fn((_spans, cb: (result: ExportResult) => void) =>
    cb({ code: ExportResultCode.SUCCESS })
  ),
  shutdown: vi.fn(() => Promise.resolve()),
  forceFlush: vi.fn(() => Promise.resolve()),
});

const exportOnce = (exporter: SpanExporter) =>
  new Promise<ExportResult>((resolve) => exporter.export(spans, resolve));

describe("TokenRefreshingExporter", () => {
  it("sends each export with the token current at that time", async () => {
    const getToken = vi
      .fn()
      .mockResolvedValueOnce("token-1")
      .mockResolvedValueOnce("token-2");
    const made: Record<string, ReturnType<typeof fakeExporter>> = {};
    const exporter = new TokenRefreshingExporter(getToken, (token) => {
      const fake = fakeExporter();
      made[token] = fake;
      return fake;
    });

    await exportOnce(exporter);
    await exportOnce(exporter);

    expect(made["token-1"]?.export).toHaveBeenCalledTimes(1);
    expect(made["token-2"]?.export).toHaveBeenCalledTimes(1);
    expect(made["token-1"]?.shutdown).toHaveBeenCalled();
  });

  it("reuses the exporter while the token is unchanged", async () => {
    const makeExporter = vi.fn(fakeExporter);
    const exporter = new TokenRefreshingExporter(
      () => Promise.resolve("token"),
      makeExporter
    );

    await exportOnce(exporter);
    await exportOnce(exporter);

    expect(makeExporter).toHaveBeenCalledTimes(1);
  });

  it("fails the export when the token cannot be fetched", async () => {
    const makeExporter = vi.fn(fakeExporter);
    const exporter = new TokenRefreshingExporter(
      () => Promise.reject(new Error("offline")),
      makeExporter
    );

    const result = await exportOnce(exporter);

    expect(result.code).toBe(ExportResultCode.FAILED);
    expect(makeExporter).not.toHaveBeenCalled();
  });
});
