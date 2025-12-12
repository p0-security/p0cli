/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { getMeter } from "./instrumentation";
import type { Counter } from "@opentelemetry/api";
import { SpanStatusCode, trace } from "@opentelemetry/api";

let proxyCommandCounter: Counter | undefined = undefined;

const getProxyCommandCounter = (): Counter => {
  if (!proxyCommandCounter) {
    const meter = getMeter();
    proxyCommandCounter = meter.createCounter("ssh.proxy_command.attempts", {
      description: "Number of proxyCommand execution attempts",
    });
  }
  return proxyCommandCounter;
};

export const observedExit = (code: number, error?: unknown) => {
  if (error || code !== 0) {
    const span = trace.getActiveSpan();
    if (span) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error ? String(error) : undefined,
      });
    }
  }
  process.exit(code);
};

export const recordProxyCommandMetric = (
  success: boolean,
  provider: string
) => {
  try {
    const counter = getProxyCommandCounter();
    counter.add(1, {
      success: success ? 1 : 0,
      provider,
    });
  } catch (error) {
    // Silently ignore metric recording errors - metrics are best-effort telemetry
  }
};
