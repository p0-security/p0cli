/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { awsCloudAuth } from "../../aws/auth";
import { generateTransferUrls } from "../index";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../aws/auth", () => ({ awsCloudAuth: vi.fn() }));
vi.mock("@aws-sdk/s3-request-presigner", () => ({
  getSignedUrl: vi.fn().mockResolvedValue("https://signed.example/url"),
}));

const ONE_HOUR = 60 * 60;
const NOW = Date.parse("2030-01-01T00:00:00Z");

describe("generateTransferUrls()", () => {
  const target = {
    bucket: "my-bucket",
    key: "uploads/user/abc/file.txt",
    awsSpec: {} as never,
  };

  // expiresIn passed to the GET and DELETE getSignedUrl calls, respectively.
  const signedExpiries = () => ({
    get: vi.mocked(getSignedUrl).mock.calls[0]![2]!.expiresIn,
    delete: vi.mocked(getSignedUrl).mock.calls[1]![2]!.expiresIn,
  });

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("uses the full configured window when credentials outlive it", async () => {
    vi.mocked(awsCloudAuth).mockResolvedValue({
      expiresAt: NOW + 2 * ONE_HOUR * 1000,
    } as never);

    const result = await generateTransferUrls({} as never, {} as never, target);

    expect(signedExpiries()).toEqual({ get: ONE_HOUR, delete: ONE_HOUR });
    expect(result.expirySeconds).toEqual({ get: ONE_HOUR, delete: ONE_HOUR });
  });

  it("caps the window to the remaining credential lifetime", async () => {
    vi.mocked(awsCloudAuth).mockResolvedValue({
      expiresAt: NOW + 300 * 1000, // 5 minutes left
    } as never);

    const result = await generateTransferUrls({} as never, {} as never, target);

    expect(signedExpiries()).toEqual({ get: 300, delete: 300 });
    expect(result.expirySeconds).toEqual({ get: 300, delete: 300 });
  });

  it("falls back to the configured window when expiry is unknown", async () => {
    vi.mocked(awsCloudAuth).mockResolvedValue({} as never);

    await generateTransferUrls({} as never, {} as never, target);

    expect(signedExpiries()).toEqual({ get: ONE_HOUR, delete: ONE_HOUR });
  });

  it("never signs a negative window when credentials are already expired", async () => {
    vi.mocked(awsCloudAuth).mockResolvedValue({
      expiresAt: NOW - 1000,
    } as never);

    await generateTransferUrls({} as never, {} as never, target);

    expect(signedExpiries()).toEqual({ get: 0, delete: 0 });
  });
});
