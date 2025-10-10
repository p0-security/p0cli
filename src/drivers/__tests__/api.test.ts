/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Authn } from "../../types/identity";
import { fetchWithStreaming } from "../api";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock dependencies
vi.mock("../config");
vi.mock("../env");
vi.mock("../../version", () => ({
  p0VersionInfo: { version: "1.0.0" },
}));

describe("fetchWithStreaming", () => {
  const mockAuthn: Authn = {
    getToken: vi.fn().mockResolvedValue("mock-token"),
    identity: {
      org: { slug: "test-org" },
    },
  } as unknown as Authn;

  beforeEach(() => {
    vi.clearAllMocks();
  });
  afterEach(() => {
    // Clear all mocks after each test
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  const createMockStreamingResponse = (chunks: string[]) => {
    const encoder = new TextEncoder();
    let chunkIndex = 0;

    const mockReader = {
      read: vi.fn().mockImplementation(async () => {
        if (chunkIndex < chunks.length) {
          const chunk = chunks[chunkIndex++];
          return {
            done: false,
            value: encoder.encode(chunk),
          };
        }
        return { done: true, value: undefined };
      }),
    };

    return {
      body: {
        getReader: vi.fn().mockReturnValue(mockReader),
      },
    };
  };

  it("should yield data from streaming response", async () => {
    const mockFetch = vi.spyOn(global, "fetch").mockResolvedValue(
      createMockStreamingResponse([
        JSON.stringify({
          type: "data",
          data: { id: "1", message: "First chunk" },
        }) + "\n",
        JSON.stringify({
          type: "data",
          data: { id: "2", message: "Second chunk" },
        }) + "\n",
      ]) as any
    );

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/command",
      method: "POST",
      body: JSON.stringify({ test: "data" }),
    });

    const results = [];
    for await (const chunk of generator) {
      results.push(chunk);
    }

    expect(results).toEqual([
      { id: "1", message: "First chunk" },
      { id: "2", message: "Second chunk" },
    ]);

    expect(mockFetch).toHaveBeenCalledWith("/command", {
      method: "POST",
      headers: {
        authorization: "Bearer mock-token",
        "Content-Type": "application/json",
        "User-Agent": "P0 CLI/1.0.0",
      },
      body: JSON.stringify({ test: "data" }),
      keepalive: true,
    });
  });

  it("should skip heartbeat messages", async () => {
    const chunks = [
      JSON.stringify({
        type: "heartbeat",
      }) + "\n",
      JSON.stringify({
        type: "data",
        data: { id: "1", message: "Real data" },
      }) + "\n",
      JSON.stringify({
        type: "heartbeat",
      }) + "\n",
    ];
    vi.spyOn(global, "fetch").mockResolvedValue(
      createMockStreamingResponse(chunks) as any
    );

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "GET",
    });

    const results = [];
    for await (const chunk of generator) {
      results.push(chunk);
    }

    expect(results).toEqual([{ id: "1", message: "Real data" }]);
  });

  it("should throw error when response type is error", async () => {
    const chunks = [
      JSON.stringify({
        type: "error",
        error: "Something went wrong",
      }) + "\n",
    ];
    vi.spyOn(global, "fetch").mockResolvedValue(
      createMockStreamingResponse(chunks) as any
    );

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "GET",
    });

    await expect(async () => {
      for await (const _chunk of generator) {
        // Should throw before yielding
      }
    }).rejects.toBe("Something went wrong");
  });

  it("should throw error when data contains error", async () => {
    const chunks = [
      JSON.stringify({
        type: "data",
        data: { error: "Data error occurred" },
      }) + "\n",
    ];
    vi.spyOn(global, "fetch").mockResolvedValue(
      createMockStreamingResponse(chunks) as any
    );

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "GET",
    });

    await expect(async () => {
      for await (const _chunk of generator) {
        // Should throw before yielding
      }
    }).rejects.toBe("Data error occurred");
  });

  it("should throw error for invalid response format", async () => {
    const chunks = [
      JSON.stringify({
        type: "unknown",
        someData: "invalid",
      }) + "\n",
    ];
    vi.spyOn(global, "fetch").mockResolvedValue(
      createMockStreamingResponse(chunks) as any
    );

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "GET",
    });

    await expect(async () => {
      for await (const _chunk of generator) {
        // Should throw before yielding
      }
    }).rejects.toBe("Invalid response from the server");
  });

  it("should handle multiple JSON objects in single chunk", async () => {
    const chunks = [
      JSON.stringify({ type: "data", data: { id: "1\ntest" } }) +
        "\n" +
        JSON.stringify({ type: "data", data: { id: "2" } }) +
        "\n",
    ];
    vi.spyOn(global, "fetch").mockResolvedValue(
      createMockStreamingResponse(chunks) as any
    );

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "GET",
    });

    const results = [];
    for await (const chunk of generator) {
      results.push(chunk);
    }

    expect(results).toEqual([{ id: "1\ntest" }, { id: "2" }]);
  });

  it("should handle chunks with partial data", async () => {
    const chunks = [
      '{"type":"data","data":{"id":"1"}}\n{"type":"heartbeat"}\n{"type":"da', // Ends mid-JSON
      'ta","data":{"id":"2"}}\n', // Completes the JSON
    ];

    vi.spyOn(global, "fetch").mockResolvedValue(
      createMockStreamingResponse(chunks) as any
    );

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "GET",
    });

    const results = [];
    for await (const chunk of generator) {
      results.push(chunk);
    }

    expect(results).toEqual([{ id: "1" }, { id: "2" }]);
  });

  it("should handle incomplete JSON across multiple chunks", async () => {
    // Simulate arbitrary chunks that split JSON objects
    const chunks = [
      '{"type":"data","data":{"id":"1","mess', // Incomplete JSON
      'age":"First chunk"}}\n{"type":"data",', // Completes first, starts second
      '"data":{"id":"2","message":"Second chu', // Middle of second JSON
      'nk"}}\n', // Completes second JSON
    ];

    vi.spyOn(global, "fetch").mockResolvedValue(
      createMockStreamingResponse(chunks) as any
    );

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "GET",
    });

    const results = [];
    for await (const chunk of generator) {
      results.push(chunk);
    }

    expect(results).toEqual([
      { id: "1", message: "First chunk" },
      { id: "2", message: "Second chunk" },
    ]);
  });

  it("should handle single character chunks", async () => {
    // Each character as a separate chunk
    const jsonString = '{"type":"data","data":{"id":"test"}}\n';
    const chunks = jsonString.split("");

    vi.spyOn(global, "fetch").mockResolvedValue(
      createMockStreamingResponse(chunks) as any
    );

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "GET",
    });

    const results = [];
    for await (const chunk of generator) {
      results.push(chunk);
    }

    expect(results).toEqual([{ id: "test" }]);
  });

  it("should handle chunks with no invalid json and no new lines", async () => {
    const chunks = [
      '{"type":"data","data":{"id":"1"}', // No newlines
    ];

    vi.spyOn(global, "fetch").mockResolvedValue(
      createMockStreamingResponse(chunks) as any
    );

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "GET",
    });

    await expect(async () => {
      for await (const _chunk of generator) {
        // Should throw before yielding
      }
    }).rejects.toBe("Invalid response from the server");
  });

  it("should handle empty chunks", async () => {
    const chunks = [
      "", // Empty chunk
      '{"type":"data","data":{"id":"1"}}\n',
      "", // Another empty chunk
      '{"type":"data","data":{"id":"2"}}\n',
    ];

    vi.spyOn(global, "fetch").mockResolvedValue(
      createMockStreamingResponse(chunks) as any
    );

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "GET",
    });

    const results = [];
    for await (const chunk of generator) {
      results.push(chunk);
    }

    expect(results).toEqual([{ id: "1" }, { id: "2" }]);
  });

  it("should throw errors if there is leftover error chunk without new-line and a type", async () => {
    const chunks = ['{"error":"Something went wrong"}'];

    vi.spyOn(global, "fetch").mockResolvedValue(
      createMockStreamingResponse(chunks) as any
    );

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "GET",
    });

    await expect(async () => {
      for await (const _chunk of generator) {
        // Should throw before yielding
      }
    }).rejects.toBe("Something went wrong");
  });

  it("should throw network error for terminated", async () => {
    vi.spyOn(global, "fetch").mockRejectedValue(new TypeError("terminated"));

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "GET",
    });

    await expect(async () => {
      for await (const _chunk of generator) {
        // Should throw before yielding
      }
    }).rejects.toBe("Network error: Unable to reach the server.");
  });

  it("should rethrow other errors", async () => {
    const customError = new Error("Custom error");
    vi.spyOn(global, "fetch").mockRejectedValue(customError);

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "GET",
    });

    await expect(async () => {
      for await (const _chunk of generator) {
        // Should throw before yielding
      }
    }).rejects.toBe(customError);
  });

  it("should throw network error for fetch failed", async () => {
    vi.spyOn(global, "fetch").mockRejectedValue(new TypeError("fetch failed"));

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "GET",
    });

    await expect(async () => {
      for await (const _chunk of generator) {
        // Should throw before yielding
      }
    }).rejects.toBe("Network error: Unable to reach the server.");
  });

  it("should throw error when no reader available", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue({
      body: null,
    } as any);

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "GET",
    });

    await expect(async () => {
      for await (const _chunk of generator) {
        // Should throw before yielding
      }
    }).rejects.toBe("No reader available");
  });

  it("should use timeout when maxTimeoutMs is provided", async () => {
    const chunks = [
      JSON.stringify({
        type: "data",
        data: { message: "success" },
      }) + "\n",
    ];

    const mockFetch = vi
      .spyOn(global, "fetch")
      .mockResolvedValue(createMockStreamingResponse(chunks) as any);

    const generator = fetchWithStreaming(mockAuthn, {
      url: "/stream",
      method: "POST",
      maxTimeoutMs: 5000,
    });

    const results = [];
    for await (const chunk of generator) {
      results.push(chunk);
    }

    expect(mockFetch).toHaveBeenCalledWith(
      "/stream",
      expect.objectContaining({
        signal: expect.any(AbortSignal),
      })
    );
  });
});
