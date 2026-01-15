/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { OTEL_INSTRUMENTATION_VERSION } from "./constants";
import type { AttributeValue, Span } from "@opentelemetry/api";
import { SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("p0cli", OTEL_INSTRUMENTATION_VERSION);

const setSpanAttributes = (
  span: Span,
  attributes?: Record<string, AttributeValue>
) => {
  if (attributes) {
    for (const [key, value] of Object.entries(attributes)) {
      span.setAttribute(key, value);
    }
  }
};

const handleSpanError = (span: Span, e: unknown): never => {
  const err = e instanceof Error ? e : new Error(`Unknown error: ${String(e)}`);
  span.recordException(err);
  span.setStatus({ code: SpanStatusCode.ERROR, message: err.message });
  throw e; // Re-throw original error to preserve type
};

/**
 * Defines a new span and executes the provided synchronous function within that span.
 *
 * The span will be properly ended even if the function throws an error, and the error will be recorded in the span.
 *
 * Please follow {@link https://opentelemetry.io/docs/concepts/semantic-conventions/ OpenTelemetry semantic conventions}
 * for naming spans and setting attributes.
 *
 * @param name the span name, must be low cardinality
 * @param fn the synchronous function to invoke within the span
 * @param attributes optional attributes to set on the span
 * @returns the result of the function execution
 */
export const traceSpanSync = <T>(
  name: string,
  fn: (span: Span) => T,
  attributes?: Record<string, AttributeValue>
): T => {
  return tracer.startActiveSpan(name, (span) => {
    setSpanAttributes(span, attributes);
    try {
      const result = fn(span);
      span.end();
      return result;
    } catch (e: unknown) {
      span.end();
      handleSpanError(span, e); // Never returns, always throws
      // TypeScript doesn't recognize `never` return type, so we need this unreachable code
      throw e; // This line is never reached but satisfies TypeScript
    }
  });
};

/**
 * Defines a new span and executes the provided function within that span.
 *
 * Supports both synchronous and asynchronous functions.
 *
 * The span will be properly ended even if the function throws an error, and the error will be recorded in the span.
 *
 * Please follow {@link https://opentelemetry.io/docs/concepts/semantic-conventions/ OpenTelemetry semantic conventions}
 * for naming spans and setting attributes.
 *
 * @param name the span name, must be low cardinality
 * @param fn the function to invoke within the span
 * @param attributes optional attributes to set on the span
 * @returns the result of the function execution
 */
export const traceSpan = async <T>(
  name: string,
  fn: (span: Span) => Promise<T> | T,
  attributes?: Record<string, AttributeValue>
): Promise<T> => {
  return await tracer.startActiveSpan(name, async (span) => {
    setSpanAttributes(span, attributes);
    try {
      const result = await fn(span);
      span.end();
      return result;
    } catch (e: unknown) {
      span.end();
      handleSpanError(span, e); // Never returns, always throws
      // TypeScript doesn't recognize `never` return type, so we need this unreachable code
      throw e; // This line is never reached but satisfies TypeScript
    }
  });
};

/**
 * Manually set a span's status to ERROR without throwing an exception.
 * Use this when an operation fails in a way that should be tracked as an error,
 * but doesn't result in an exception (e.g., business logic failures, request denials).
 *
 * @param span the span to mark as error
 * @param message error message describing what went wrong
 */
export const markSpanError = (span: Span, message: string): void => {
  span.setStatus({ code: SpanStatusCode.ERROR, message });
};

/**
 * Manually set a span's status to OK.
 * Use this when an operation succeeds and you want to explicitly mark it as successful.
 *
 * @param span the span to mark as successful
 */
export const markSpanOk = (span: Span): void => {
  span.setStatus({ code: SpanStatusCode.OK });
};
