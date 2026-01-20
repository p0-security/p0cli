# OpenTelemetry Error Handling Architecture

## Overview

This document describes the three-layer error handling architecture implemented for OpenTelemetry instrumentation in the P0 CLI.

## Background

The CLI uses OpenTelemetry for observability, sending spans to the P0 backend for monitoring command usage and debugging failures. Error tracking is critical for identifying issues in production.

## Architecture

### Three-Layer Error Handling

The CLI uses three complementary layers to ensure comprehensive error tracking:

#### Layer 1: `traceSpan()` Wrapper (Automatic Exception Handling)

**Purpose:** Automatically catch and record thrown exceptions within instrumented operations.

**Implementation:** `src/opentelemetry/otel-helpers.ts`

```typescript
await traceSpan(
  "command.name",
  async (span) => {
    span.setAttribute("key", value);
    // Command logic here
    // Exceptions automatically caught and recorded
  },
  { command: "command_name" }
);
```

**What it does:**

- Creates a new span for the operation
- Catches any thrown exceptions
- Records the exception in the span
- Marks the span status as ERROR
- Re-throws the original error (preserves error type)
- Always ends the span, even on error

**When to use:** Wrap all command actions and significant operations that should be tracked.

#### Layer 2: Explicit `markSpanError()` (Non-Exception Failures)

**Purpose:** Handle failures that don't throw exceptions (exit codes, business logic failures).

**Implementation:** Manual calls to `markSpanError(span, message)`

```typescript
const exitCode = await someOperation();
if (exitCode !== 0) {
  span.setAttribute("operation.exitCode", exitCode);
  markSpanError(span, "Operation failed");
  return exitCode;
}
```

**What it does:**

- Manually sets span status to ERROR with a message
- Allows adding context-specific attributes before marking
- Doesn't throw or alter control flow

**When to use:**

- Process returns non-zero exit code but doesn't throw
- Business logic determines an operation failed
- Need to add diagnostic attributes alongside error marking

**Example:** `src/plugins/ssh/index.ts:582-586` marks SSH pre-test failures with exit code and phase information.

#### Layer 3: Global `.fail()` Handler (Safety Net)

**Purpose:** Catch all Yargs command failures that escape other handlers.

**Implementation:** `src/commands/index.ts:95-120`

```typescript
.fail((message, error, yargs) => {
  try {
    const activeSpan = trace.getActiveSpan();
    if (activeSpan) {
      const errorMessage = error ? String(error) : message;
      markSpanError(activeSpan, errorMessage);
    }
  } catch (e) {
    // Silently ignore telemetry failures
  }

  print2(/* error output */);
  exitProcess(1);
});
```

**What it does:**

- Yargs calls this handler on any command failure (invalid args, missing commands, etc.)
- Marks the currently active span as error (if one exists)
- Defensively wrapped in try/catch to prevent telemetry from breaking CLI
- Uses `exitProcess(1)` to ensure spans are properly ended before exit

**When to use:** Automatically invoked by Yargs - no action needed for new commands.

## Why Three Layers?

Each layer serves a distinct purpose:

1. **Layer 1** handles the common case: exceptions thrown during operations
2. **Layer 2** handles the uncommon case: graceful failures without exceptions
3. **Layer 3** handles the edge case: errors before/outside of instrumentation

This redundancy is intentional - better to have overlapping coverage than gaps in error tracking.

## Defensive Error Handling

**Critical principle:** Telemetry must never break CLI functionality.

All OpenTelemetry operations are wrapped in try/catch blocks:

```typescript
try {
  const activeSpan = trace.getActiveSpan();
  if (activeSpan) {
    markSpanError(activeSpan, message);
  }
} catch (e) {
  // Silently ignore - CLI functionality takes precedence
}
```

This ensures that if the OpenTelemetry SDK throws an exception, deadlocks, or behaves unexpectedly, the CLI continues to work.

## Process Exit Handling

Always use `exitProcess()` instead of `process.exit()`:

```typescript
import { exitProcess } from "../opentelemetry/otel-helpers";

// Later...
if (process.env.NODE_ENV !== "unit") {
  exitProcess(exitCode ?? 0);
}
```

**Why:** `exitProcess()` ensures the active span is properly marked (if error) and ended before the process terminates. Direct `process.exit()` calls bypass span cleanup.

## Instrumenting New Commands

To add instrumentation to a new command:

1. Import the helper:

   ```typescript
   import { traceSpan } from "../opentelemetry/otel-helpers";
   ```

2. Wrap the command action:

   ```typescript
   const commandAction = async (args) => {
     await traceSpan(
       "command_name.command", // Span name (low cardinality)
       async (span) => {
         // Add attributes
         span.setAttribute("arg_name", args.value);

         // Existing command logic
         await doCommandWork(args);

         // Use exitProcess if needed
         if (process.env.NODE_ENV !== "unit") {
           exitProcess(exitCode ?? 0);
         }
       },
       { command: "command_name" } // Root attribute
     );
   };
   ```

3. That's it! Exceptions are automatically caught, and the `.fail()` handler provides backup.

## Testing

When testing instrumented commands:

- Mock `@opentelemetry/api` to avoid real telemetry calls
- Mock `exitProcess` to prevent test runner termination
- Verify spans are created with correct attributes
- Test error scenarios to ensure spans are marked as errors
- Verify CLI still works even if telemetry throws exceptions

See `src/commands/__tests__/index.test.ts` and `src/opentelemetry/__tests__/otel-helpers.test.ts` for examples.

## Current Status

**Implemented:**

- ✅ Layer 1: `traceSpan()` and `traceSpanSync()` wrappers
- ✅ Layer 2: `markSpanError()` and `markSpanOk()` helpers
- ✅ Layer 3: Global `.fail()` handler in Yargs CLI
- ✅ `exitProcess()` for proper span lifecycle management
- ✅ Tests for all error handling layers

**Instrumented commands:**

- `ssh` - Full instrumentation with span wrapper
- `scp` - Full instrumentation with span wrapper
- `rdp` - Uses `exitProcess()` but no span wrapper yet

**Next steps:**

- Monitor production telemetry to validate `.fail()` handler effectiveness
- Consider instrumenting high-value commands (`ls`, `request`, `grant`, `allow`)
- Evaluate if boilerplate reduction is needed after 5+ commands instrumented

## References

- OpenTelemetry semantic conventions: https://opentelemetry.io/docs/concepts/semantic-conventions/
- Implementation: `src/opentelemetry/otel-helpers.ts`
- Tests: `src/opentelemetry/__tests__/otel-helpers.test.ts`
- Example usage: `src/commands/ssh.ts`, `src/commands/scp.ts`
