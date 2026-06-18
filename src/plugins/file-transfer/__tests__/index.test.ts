/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { awsCloudAuth } from "../../aws/auth";
import type { AwsResourcePermissionSpec } from "../../aws/types";
import { generateSignedUrl } from "../index";
import { GetObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../aws/auth", () => ({ awsCloudAuth: vi.fn() }));
vi.mock("@aws-sdk/s3-request-presigner", () => ({
  getSignedUrl: vi.fn().mockResolvedValue("https://signed.example/url"),
}));
vi.mock("@aws-sdk/client-s3", () => ({
  DeleteObjectCommand: vi.fn(),
  GetObjectCommand: vi.fn(),
}));

const ONE_HOUR = 60 * 60;
const NOW = Date.parse("2030-01-01T00:00:00Z");
const defaultCredentials = {
  AWS_ACCESS_KEY_ID: "test",
  AWS_SECRET_ACCESS_KEY: "test",
  AWS_SESSION_TOKEN: "test",
  AWS_SECURITY_TOKEN: "test",
};

describe("generateTransferUrl()", () => {
  const target = {
    bucket: "my-bucket",
    key: "uploads/user/abc/file.txt",
    awsSpec: {
      type: "aws",
      permission: {
        account: "test-account",
        accountId: "123456789012",
        arn: "arn:aws:iam::123456789012:role/test",
        name: "test-role",
        idcId: undefined,
        idcRegion: undefined,
      },
      generated: { name: "test-role" },
      delegation: {},
    } satisfies AwsResourcePermissionSpec,
  };

  const authn = {} as any;
  const s3 = {} as any;

  // expiresIn passed to the getSignedUrl call.
  const signedExpiries = () =>
    vi.mocked(getSignedUrl).mock.calls[0]![2]!.expiresIn;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    vi.mocked(awsCloudAuth).mockResolvedValue({
      ...defaultCredentials,
      expiresAt: NOW + 2 * ONE_HOUR * 1000, // future time that won't be expired
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("uses the full configured window when credentials outlive it", async () => {
    vi.mocked(awsCloudAuth).mockResolvedValue({
      ...defaultCredentials,
      expiresAt: NOW + 2 * ONE_HOUR * 1000,
    });

    const result = await generateSignedUrl(authn, s3, target, "get");

    expect(signedExpiries()).toBe(ONE_HOUR);
    expect(result.expirySeconds).toBe(ONE_HOUR);
  });

  it("caps the window to the remaining credential lifetime", async () => {
    vi.mocked(awsCloudAuth).mockResolvedValue({
      ...defaultCredentials,
      expiresAt: NOW + 300 * 1000, // 5 minutes left
    });

    const result = await generateSignedUrl(authn, s3, target, "get");

    expect(signedExpiries()).toBe(300);
    expect(result.expirySeconds).toBe(300);
  });

  it("falls back to the configured window when expiry is unknown", async () => {
    vi.mocked(awsCloudAuth).mockResolvedValue({ ...defaultCredentials });

    await generateSignedUrl(authn, s3, target, "get");

    expect(signedExpiries()).toBe(ONE_HOUR);
  });

  it("throws when credentials are already expired", async () => {
    vi.mocked(awsCloudAuth).mockResolvedValue({
      ...defaultCredentials,
      expiresAt: NOW - 1000,
    });

    await expect(generateSignedUrl(authn, s3, target, "get")).rejects.toThrow(
      /too soon to sign usable URLs/
    );
  });

  it("throws when credentials expire below the usable threshold", async () => {
    vi.mocked(awsCloudAuth).mockResolvedValue({
      ...defaultCredentials,
      expiresAt: NOW + 30 * 1000, // 30s left, below 60s threshold
    });

    await expect(generateSignedUrl(authn, s3, target, "get")).rejects.toThrow(
      /too soon to sign usable URLs/
    );
  });

  it("correctly generates get signed URL when get command passed in", async () => {
    const result = await generateSignedUrl(authn, s3, target, "get");
    expect(result.signedUrl).toBe("https://signed.example/url");
    expect(GetObjectCommand).toHaveBeenCalledOnce();
    expect(DeleteObjectCommand).not.toHaveBeenCalled();
  });

  it("correctly generates delete signed URL when delete command passed in", async () => {
    const result = await generateSignedUrl(authn, s3, target, "delete");
    expect(result.signedUrl).toBe("https://signed.example/url");
    expect(DeleteObjectCommand).toHaveBeenCalledOnce();
    expect(GetObjectCommand).not.toHaveBeenCalled();
  });
});
