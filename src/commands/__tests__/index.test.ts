/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { getCli } from "../index";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Type for our mock span
type MockSpan = {
  setAttribute: ReturnType<typeof vi.fn>;
  setStatus: ReturnType<typeof vi.fn>;
  recordException: ReturnType<typeof vi.fn>;
  end: ReturnType<typeof vi.fn>;
};

// Shared state to track the active span
let mockActiveSpan: MockSpan | null = null;

// Mock OpenTelemetry API
vi.mock("@opentelemetry/api", async () => {
  const actual = await vi.importActual("@opentelemetry/api");

  return {
    ...actual,
    trace: {
      getTracer: vi.fn(() => ({
        startActiveSpan: vi.fn((_name, fn) => {
          const span = {
            setAttribute: vi.fn(),
            setStatus: vi.fn(),
            recordException: vi.fn(),
            end: vi.fn(),
          };
          mockActiveSpan = span;
          return fn(span);
        }),
      })),
      getActiveSpan: vi.fn(() => mockActiveSpan),
    },
    SpanStatusCode: {
      OK: 1,
      ERROR: 2,
      UNSET: 0,
    },
  };
});

// Mock exitProcess to prevent actual exit
vi.mock("../../opentelemetry/otel-helpers", async () => {
  const actual = await vi.importActual<
    typeof import("../../opentelemetry/otel-helpers")
  >("../../opentelemetry/otel-helpers");

  return {
    ...actual,
    exitProcess: vi.fn((code: number) => {
      throw new Error(`exitProcess called with code ${code}`);
    }),
  };
});

// Mock print2 to suppress error output during tests
vi.mock("../../drivers/stdio", () => ({
  print1: vi.fn(),
  print2: vi.fn(),
}));

// Mock config to prevent actual config loading
vi.mock("../../drivers/config", () => ({
  getHelpMessage: vi.fn(() => "For help, visit https://p0.dev"),
}));

// Mock version check middleware
vi.mock("../../middlewares/version", () => ({
  checkVersion: vi.fn(),
}));

// Mock all command modules to prevent actual command registration
vi.mock("../allow", () => ({
  allowCommand: vi.fn((yargs) => yargs),
}));
vi.mock("../aws", () => ({
  awsCommand: vi.fn((yargs) => yargs),
}));
vi.mock("../grant", () => ({
  grantCommand: vi.fn((yargs) => yargs),
}));
vi.mock("../kubeconfig", () => ({
  kubeconfigCommand: vi.fn((yargs) => yargs),
}));
vi.mock("../login", () => ({
  loginCommand: vi.fn((yargs) => yargs),
}));
vi.mock("../logout", () => ({
  logoutCommand: vi.fn((yargs) => yargs),
}));
vi.mock("../ls", () => ({
  lsCommand: vi.fn((yargs) => yargs),
}));
vi.mock("../print-bearer-token", () => ({
  printBearerTokenCommand: vi.fn((yargs) => yargs),
}));
vi.mock("../rdp", () => ({
  rdpCommand: vi.fn((yargs) => yargs),
}));
vi.mock("../request", () => ({
  requestCommand: vi.fn((yargs) => yargs),
}));
vi.mock("../scp", () => ({
  scpCommand: vi.fn((yargs) => yargs),
}));
vi.mock("../ssh", () => ({
  sshCommand: vi.fn((yargs) => yargs),
}));
vi.mock("../ssh-proxy", () => ({
  sshProxyCommand: vi.fn((yargs) => yargs),
}));
vi.mock("../ssh-resolve", () => ({
  sshResolveCommand: vi.fn((yargs) => yargs),
}));

describe("getCli - .fail() handler", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockActiveSpan = null;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should mark active span as error when command fails with error object", async () => {
    // Create a mock active span
    mockActiveSpan = {
      setAttribute: vi.fn(),
      setStatus: vi.fn(),
      recordException: vi.fn(),
      end: vi.fn(),
    };

    const cli = await getCli();

    // Trigger a command failure by not providing required command
    try {
      await cli.parseAsync([]);
      expect.fail("Should have thrown");
    } catch (error) {
      expect((error as Error).message).toContain(
        "exitProcess called with code 1"
      );
    }

    // Verify span was marked as error
    expect(mockActiveSpan.setStatus).toHaveBeenCalledWith({
      code: 2, // ERROR
      message: expect.stringContaining("Not enough non-option arguments"),
    });
  });

  it("should not throw if no active span exists when command fails", async () => {
    // Set no active span
    mockActiveSpan = null;

    const cli = await getCli();

    // Should not throw due to telemetry, only due to exitProcess
    try {
      await cli.parseAsync([]);
      expect.fail("Should have thrown");
    } catch (error) {
      expect((error as Error).message).toContain(
        "exitProcess called with code 1"
      );
    }
  });

  it("should call exitProcess with code 1 on command failure", async () => {
    const { exitProcess } = await import("../../opentelemetry/otel-helpers.js");

    const cli = await getCli();

    try {
      await cli.parseAsync([]);
      expect.fail("Should have thrown");
    } catch (error) {
      expect((error as Error).message).toContain(
        "exitProcess called with code 1"
      );
    }

    expect(exitProcess).toHaveBeenCalledWith(1);
  });

  it("should handle telemetry failures gracefully without breaking CLI", async () => {
    // Create a mock span that throws when setStatus is called
    mockActiveSpan = {
      setAttribute: vi.fn(),
      setStatus: vi.fn(() => {
        throw new Error("Telemetry failure");
      }),
      recordException: vi.fn(),
      end: vi.fn(),
    };

    const cli = await getCli();

    // Should still exit via exitProcess despite telemetry error
    try {
      await cli.parseAsync([]);
      expect.fail("Should have thrown");
    } catch (error) {
      expect((error as Error).message).toContain(
        "exitProcess called with code 1"
      );
    }

    // Verify it attempted to mark the span (and failed)
    expect(mockActiveSpan.setStatus).toHaveBeenCalled();
  });

  it("should convert error object to string when marking span", async () => {
    mockActiveSpan = {
      setAttribute: vi.fn(),
      setStatus: vi.fn(),
      recordException: vi.fn(),
      end: vi.fn(),
    };

    const cli = await getCli();

    // Trigger failure
    try {
      await cli.parseAsync([]);
      expect.fail("Should have thrown");
    } catch (error) {
      expect((error as Error).message).toContain("exitProcess");
    }

    // Verify the error was converted to string
    expect(mockActiveSpan.setStatus).toHaveBeenCalledWith({
      code: 2,
      message: expect.any(String),
    });
  });
});
