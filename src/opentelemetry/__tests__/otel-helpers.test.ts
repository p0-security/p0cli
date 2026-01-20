/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  exitProcess,
  markSpanError,
  markSpanOk,
  traceSpan,
  traceSpanSync,
} from "../otel-helpers";
import type { Span } from "@opentelemetry/api";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Type for our mock span
type MockSpan = {
  setAttribute: ReturnType<typeof vi.fn>;
  setStatus: ReturnType<typeof vi.fn>;
  recordException: ReturnType<typeof vi.fn>;
  end: ReturnType<typeof vi.fn>;
};

// Shared state to track the last created span
let lastMockSpan: MockSpan | null = null;

// Mock OpenTelemetry API
vi.mock("@opentelemetry/api", async () => {
  const actual = await vi.importActual("@opentelemetry/api");

  return {
    ...actual,
    trace: {
      getTracer: vi.fn(() => ({
        startActiveSpan: vi.fn((_name, fn) => {
          // Create a new mock span
          lastMockSpan = {
            setAttribute: vi.fn(),
            setStatus: vi.fn(),
            recordException: vi.fn(),
            end: vi.fn(),
          };
          return fn(lastMockSpan);
        }),
      })),
      getActiveSpan: vi.fn(() => lastMockSpan),
    },
    SpanStatusCode: {
      OK: 1,
      ERROR: 2,
      UNSET: 0,
    },
  };
});

// Mock span factory for test usage
const createMockSpan = (): Span =>
  ({
    setAttribute: vi.fn(),
    setStatus: vi.fn(),
    recordException: vi.fn(),
    end: vi.fn(),
  }) as unknown as Span;

// Helper to get the mock span with null check
const getMockSpan = (): MockSpan => {
  if (!lastMockSpan) {
    throw new Error("Mock span not initialized");
  }
  return lastMockSpan;
};

describe("traceSpan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ===== PRIORITY 1: Core Functionality =====

  it("should create and end span on successful execution", async () => {
    const result = await traceSpan("test.operation", async () => {
      return "success";
    });

    expect(result).toBe("success");

    const mockSpan = getMockSpan();
    expect(mockSpan.end).toHaveBeenCalledTimes(1);
  });

  it("should record exception and mark span as error when function throws Error", async () => {
    const error = new Error("Test error");

    await expect(
      traceSpan("test.operation", async () => {
        throw error;
      })
    ).rejects.toThrow(error);

    const mockSpan = getMockSpan();
    expect(mockSpan.recordException).toHaveBeenCalledWith(error);
    expect(mockSpan.setStatus).toHaveBeenCalledWith({
      code: 2, // ERROR
      message: "Test error",
    });
    expect(mockSpan.end).toHaveBeenCalledTimes(1);
  });

  it("should preserve original error type when re-throwing string errors", async () => {
    // This validates the fix for issue #2 - string errors should stay as strings
    const stringError =
      "Azure SSH does not currently support specifying a port";

    let caughtError: unknown;
    try {
      await traceSpan("test.operation", async () => {
        throw stringError;
      });
    } catch (e) {
      caughtError = e;
    }

    // Should be the exact same reference, not wrapped in Error
    expect(caughtError).toBe(stringError);
    expect(typeof caughtError).toBe("string");
  });

  it("should set custom attributes on span", async () => {
    await traceSpan("ssh.command", async () => "result", {
      command: "ssh",
      provider: "aws",
      sudo: true,
    });

    const mockSpan = getMockSpan();
    expect(mockSpan.setAttribute).toHaveBeenCalledWith("command", "ssh");
    expect(mockSpan.setAttribute).toHaveBeenCalledWith("provider", "aws");
    expect(mockSpan.setAttribute).toHaveBeenCalledWith("sudo", true);
  });

  it("should end span even when function throws", async () => {
    await expect(
      traceSpan("test.operation", async () => {
        throw new Error("Failure");
      })
    ).rejects.toThrow("Failure");

    const mockSpan = getMockSpan();
    expect(mockSpan.end).toHaveBeenCalledTimes(1);
  });

  // ===== PRIORITY 2: Edge Cases =====

  it("should handle Error objects correctly", async () => {
    const error = new Error("Standard error");
    error.stack = "Error: Standard error\n    at test.ts:1:1";

    await expect(
      traceSpan("test.operation", async () => {
        throw error;
      })
    ).rejects.toThrow(error);

    const mockSpan = getMockSpan();
    expect(mockSpan.recordException).toHaveBeenCalledWith(error);
    expect(mockSpan.setStatus).toHaveBeenCalledWith({
      code: 2,
      message: "Standard error",
    });
  });

  it("should handle string throws correctly", async () => {
    const stringError = "Could not determine host identifier";

    let caughtError: unknown;
    try {
      await traceSpan("test.operation", async () => {
        throw stringError;
      });
    } catch (e) {
      caughtError = e;
    }

    expect(caughtError).toBe(stringError);

    const mockSpan = getMockSpan();
    // Should still record it as an exception (wrapped in Error for telemetry)
    expect(mockSpan.recordException).toHaveBeenCalled();
    expect(mockSpan.setStatus).toHaveBeenCalledWith({
      code: 2,
      message: "Unknown error: Could not determine host identifier",
    });
  });

  it("should handle number throws correctly", async () => {
    const numberError = 404;

    let caughtError: unknown;
    try {
      await traceSpan("test.operation", async () => {
        throw numberError;
      });
    } catch (e) {
      caughtError = e;
    }

    expect(caughtError).toBe(404);

    const mockSpan = getMockSpan();
    expect(mockSpan.setStatus).toHaveBeenCalledWith({
      code: 2,
      message: "Unknown error: 404",
    });
  });

  it("should handle null/undefined throws correctly", async () => {
    let caughtError: unknown;
    try {
      await traceSpan("test.operation", async () => {
        throw null;
      });
    } catch (e) {
      caughtError = e;
    }

    expect(caughtError).toBe(null);

    const mockSpan = getMockSpan();
    expect(mockSpan.setStatus).toHaveBeenCalledWith({
      code: 2,
      message: "Unknown error: null",
    });
  });

  it("should handle async rejection", async () => {
    const error = new Error("Async rejection");

    await expect(
      traceSpan("test.operation", async () => {
        return Promise.reject(error);
      })
    ).rejects.toThrow(error);

    const mockSpan = getMockSpan();
    expect(mockSpan.recordException).toHaveBeenCalledWith(error);
    expect(mockSpan.end).toHaveBeenCalledTimes(1);
  });

  it("should support synchronous functions", async () => {
    // traceSpan accepts both sync and async functions
    const result = await traceSpan("test.operation", () => {
      return "sync result";
    });

    expect(result).toBe("sync result");

    const mockSpan = getMockSpan();
    expect(mockSpan.end).toHaveBeenCalledTimes(1);
  });

  it("should work without custom attributes", async () => {
    const result = await traceSpan("test.operation", async () => "result");

    expect(result).toBe("result");

    const mockSpan = getMockSpan();
    expect(mockSpan.end).toHaveBeenCalledTimes(1);
    // setAttribute should not be called if no attributes provided
    expect(mockSpan.setAttribute).not.toHaveBeenCalled();
  });
});

describe("traceSpanSync", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should work for synchronous functions", () => {
    const result = traceSpanSync("test.sync", () => {
      return "sync result";
    });

    expect(result).toBe("sync result");

    const mockSpan = getMockSpan();
    expect(mockSpan.end).toHaveBeenCalledTimes(1);
  });

  it("should handle synchronous exceptions", () => {
    const error = new Error("Sync error");

    expect(() =>
      traceSpanSync("test.sync", () => {
        throw error;
      })
    ).toThrow(error);

    const mockSpan = getMockSpan();
    expect(mockSpan.recordException).toHaveBeenCalledWith(error);
    expect(mockSpan.setStatus).toHaveBeenCalledWith({
      code: 2,
      message: "Sync error",
    });
    expect(mockSpan.end).toHaveBeenCalledTimes(1);
  });

  it("should preserve original error type in sync context", () => {
    const stringError = "Exactly one host must be remote";

    let caughtError: unknown;
    try {
      traceSpanSync("test.sync", () => {
        throw stringError;
      });
    } catch (e) {
      caughtError = e;
    }

    expect(caughtError).toBe(stringError);
    expect(typeof caughtError).toBe("string");
  });

  it("should set custom attributes in sync context", () => {
    traceSpanSync("test.sync", () => "result", {
      operation: "copy",
      recursive: true,
    });

    const mockSpan = getMockSpan();
    expect(mockSpan.setAttribute).toHaveBeenCalledWith("operation", "copy");
    expect(mockSpan.setAttribute).toHaveBeenCalledWith("recursive", true);
  });
});

describe("markSpanError", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should set span status to ERROR with message", () => {
    const mockSpan = createMockSpan();
    markSpanError(mockSpan, "SSH connection pre-test failed");

    expect(mockSpan.setStatus).toHaveBeenCalledWith({
      code: 2, // ERROR
      message: "SSH connection pre-test failed",
    });
  });

  it("should not throw when marking error", () => {
    const mockSpan = createMockSpan();

    expect(() => {
      markSpanError(mockSpan, "Some error message");
    }).not.toThrow();
  });

  it("should work with empty message", () => {
    const mockSpan = createMockSpan();
    markSpanError(mockSpan, "");

    expect(mockSpan.setStatus).toHaveBeenCalledWith({
      code: 2,
      message: "",
    });
  });
});

describe("markSpanOk", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should set span status to OK", () => {
    const mockSpan = createMockSpan();
    markSpanOk(mockSpan);

    expect(mockSpan.setStatus).toHaveBeenCalledWith({
      code: 1, // OK
    });
  });

  it("should not throw when marking ok", () => {
    const mockSpan = createMockSpan();

    expect(() => {
      markSpanOk(mockSpan);
    }).not.toThrow();
  });
});

describe("exitProcess", () => {
  let processExitSpy: import("vitest").MockInstance<typeof process.exit>;

  beforeEach(() => {
    vi.clearAllMocks();
    // Mock process.exit to prevent actual exit during tests
    processExitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("Process exit called");
    });
  });

  afterEach(() => {
    processExitSpy.mockRestore();
  });

  it("should exit with code 0 without marking span as error", () => {
    // Set up lastMockSpan with a fresh mock
    lastMockSpan = {
      setAttribute: vi.fn(),
      setStatus: vi.fn(),
      recordException: vi.fn(),
      end: vi.fn(),
    };

    expect(() => exitProcess(0)).toThrow("Process exit called");

    expect(lastMockSpan.setStatus).not.toHaveBeenCalled();
    expect(lastMockSpan.end).toHaveBeenCalledTimes(1);
    expect(processExitSpy).toHaveBeenCalledWith(0);
  });

  it("should exit with non-zero code and mark span as error", () => {
    // Set up lastMockSpan with a fresh mock
    lastMockSpan = {
      setAttribute: vi.fn(),
      setStatus: vi.fn(),
      recordException: vi.fn(),
      end: vi.fn(),
    };

    expect(() => exitProcess(1)).toThrow("Process exit called");

    expect(lastMockSpan.setStatus).toHaveBeenCalledWith({
      code: 2, // ERROR
      message: "Process exiting with code 1",
    });
    expect(lastMockSpan.end).toHaveBeenCalledTimes(1);
    expect(processExitSpy).toHaveBeenCalledWith(1);
  });

  it("should handle exit when no active span exists", () => {
    // Set lastMockSpan to null to simulate no active span
    lastMockSpan = null;

    expect(() => exitProcess(0)).toThrow("Process exit called");

    expect(processExitSpy).toHaveBeenCalledWith(0);
  });

  it("should end span before calling process.exit", () => {
    const callOrder: string[] = [];

    // Set up lastMockSpan with tracking
    lastMockSpan = {
      setAttribute: vi.fn(),
      setStatus: vi.fn(),
      recordException: vi.fn(),
      end: vi.fn(() => {
        callOrder.push("span.end");
      }),
    };

    processExitSpy.mockImplementation(() => {
      callOrder.push("process.exit");
      throw new Error("Process exit called");
    });

    expect(() => exitProcess(0)).toThrow("Process exit called");

    expect(callOrder).toEqual(["span.end", "process.exit"]);
  });

  it("should mark error before ending span on non-zero exit", () => {
    const callOrder: string[] = [];

    // Set up lastMockSpan with tracking
    lastMockSpan = {
      setAttribute: vi.fn(),
      setStatus: vi.fn(() => {
        callOrder.push("setStatus");
      }),
      recordException: vi.fn(),
      end: vi.fn(() => {
        callOrder.push("span.end");
      }),
    };

    processExitSpy.mockImplementation(() => {
      callOrder.push("process.exit");
      throw new Error("Process exit called");
    });

    expect(() => exitProcess(1)).toThrow("Process exit called");

    expect(callOrder).toEqual(["setStatus", "span.end", "process.exit"]);
  });
});
