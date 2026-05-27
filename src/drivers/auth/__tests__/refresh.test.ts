/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { getClientId, getProviderDomain } from "../../../types/authUtils";
import { Identity } from "../../../types/identity";
import { TokenResponse } from "../../../types/oidc";
import {
  REFRESH_FAILED,
  mergeRefreshedCredential,
  refreshOktaTokens,
  revokeOktaRefreshToken,
} from "../refresh";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../types/authUtils");
vi.mock("../../stdio");

const baseCredential: TokenResponse = {
  access_token: "old-at",
  id_token: "old-id",
  refresh_token: "old-rt",
  token_type: "Bearer",
  scope: "openid email profile okta.apps.sso offline_access",
  expires_in: 3600,
  expiry: "old-expiry",
  device_secret: "old-device-secret",
};

const buildIdentity = (overrides?: Partial<TokenResponse>): Identity =>
  ({
    org: { slug: "test-org" },
    credential: { ...baseCredential, ...overrides },
  }) as unknown as Identity;

describe("mergeRefreshedCredential", () => {
  it("prefers refreshed fields and preserves device_secret", () => {
    const refreshed: TokenResponse = {
      access_token: "new-at",
      id_token: "new-id",
      refresh_token: "new-rt",
      token_type: "Bearer",
      scope: "openid email profile okta.apps.sso offline_access",
      expires_in: 3600,
      expiry: "new-expiry",
    };
    const merged = mergeRefreshedCredential(baseCredential, refreshed);
    expect(merged.access_token).toBe("new-at");
    expect(merged.id_token).toBe("new-id");
    expect(merged.refresh_token).toBe("new-rt");
    expect(merged.expiry).toBe("new-expiry");
    // device_secret is never returned on refresh; must come from previous.
    expect(merged.device_secret).toBe("old-device-secret");
  });

  it("preserves the previous refresh_token when rotation is off", () => {
    const refreshed: TokenResponse = {
      access_token: "new-at",
      id_token: "new-id",
      // No refresh_token — Okta tenant with rotation disabled.
      token_type: "Bearer",
      expires_in: 3600,
      expiry: "new-expiry",
    };
    const merged = mergeRefreshedCredential(baseCredential, refreshed);
    expect(merged.refresh_token).toBe("old-rt");
  });

  it("falls back to previous scope when refresh response omits it (RFC 6749 §6)", () => {
    const refreshed: TokenResponse = {
      access_token: "new-at",
      id_token: "new-id",
      // No scope — per RFC means "identical to original grant".
      expires_in: 3600,
      expiry: "new-expiry",
    };
    const merged = mergeRefreshedCredential(baseCredential, refreshed);
    expect(merged.scope).toBe(baseCredential.scope);
  });

  it("uses refreshed scope when present (capturing narrowed grants)", () => {
    const refreshed: TokenResponse = {
      access_token: "new-at",
      id_token: "new-id",
      scope: "openid email",
      expires_in: 3600,
      expiry: "new-expiry",
    };
    const merged = mergeRefreshedCredential(baseCredential, refreshed);
    expect(merged.scope).toBe("openid email");
  });
});

describe("refreshOktaTokens", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getProviderDomain).mockReturnValue("example.okta.com");
    vi.mocked(getClientId).mockReturnValue("mock-client-id");
  });

  it("returns the merged credential on a successful refresh", async () => {
    const newTokens = {
      access_token: "new-at",
      id_token: "new-id",
      refresh_token: "new-rt",
      token_type: "Bearer",
      expires_in: 3600,
      expiry: "new-expiry",
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue(newTokens),
      })
    );

    const result = await refreshOktaTokens(buildIdentity());

    expect(result.access_token).toBe("new-at");
    expect(result.refresh_token).toBe("new-rt");
    expect(result.device_secret).toBe("old-device-secret");
  });

  it("preserves the stored refresh_token when rotation is off", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({
          access_token: "new-at",
          id_token: "new-id",
          // No refresh_token.
          expires_in: 3600,
          expiry: "new-expiry",
        }),
      })
    );

    const result = await refreshOktaTokens(buildIdentity());
    expect(result.refresh_token).toBe("old-rt");
  });

  it("throws REFRESH_FAILED/no_refresh_token when identity lacks an RT", async () => {
    const identity = buildIdentity({ refresh_token: undefined });
    await expect(refreshOktaTokens(identity)).rejects.toMatchObject({
      code: REFRESH_FAILED,
      reason: "no_refresh_token",
    });
  });

  it("throws REFRESH_FAILED/missing_provider_config when domain is missing", async () => {
    vi.mocked(getProviderDomain).mockReturnValue(undefined);
    await expect(refreshOktaTokens(buildIdentity())).rejects.toMatchObject({
      code: REFRESH_FAILED,
      reason: "missing_provider_config",
    });
  });

  it("throws REFRESH_FAILED/http_error on non-2xx response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        statusText: "Bad Request",
        text: vi.fn().mockResolvedValue('{"error":"invalid_grant"}'),
      })
    );

    await expect(refreshOktaTokens(buildIdentity())).rejects.toMatchObject({
      code: REFRESH_FAILED,
      reason: "http_error",
    });
  });

  it("throws REFRESH_FAILED/missing_id_token when the response omits id_token", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({
          access_token: "new-at",
          // No id_token — Firebase auth re-bootstrap would later fail.
          expires_in: 3600,
          expiry: "new-expiry",
        }),
      })
    );

    await expect(refreshOktaTokens(buildIdentity())).rejects.toMatchObject({
      code: REFRESH_FAILED,
      reason: "missing_id_token",
    });
  });

  it("throws REFRESH_FAILED/network_error when fetch itself rejects", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("ECONNREFUSED"))
    );

    await expect(refreshOktaTokens(buildIdentity())).rejects.toMatchObject({
      code: REFRESH_FAILED,
      reason: "network_error",
    });
  });
});

describe("revokeOktaRefreshToken", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getProviderDomain).mockReturnValue("example.okta.com");
    vi.mocked(getClientId).mockReturnValue("mock-client-id");
  });

  it("posts to /oauth2/v1/revoke with the stored refresh_token", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);

    await revokeOktaRefreshToken(buildIdentity());

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("https://example.okta.com/oauth2/v1/revoke");
    expect(init.method).toBe("POST");
    expect(init.body).toContain("token=old-rt");
    expect(init.body).toContain("token_type_hint=refresh_token");
    expect(init.body).toContain("client_id=mock-client-id");
  });

  it("is a no-op when no refresh_token is stored", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await revokeOktaRefreshToken(buildIdentity({ refresh_token: undefined }));

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("swallows non-2xx responses without throwing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
      })
    );

    await expect(
      revokeOktaRefreshToken(buildIdentity())
    ).resolves.toBeUndefined();
  });

  it("swallows network errors without throwing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("ECONNREFUSED"))
    );

    await expect(
      revokeOktaRefreshToken(buildIdentity())
    ).resolves.toBeUndefined();
  });

  it("skips silently when provider config is missing", async () => {
    vi.mocked(getProviderDomain).mockReturnValue(undefined);
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await revokeOktaRefreshToken(buildIdentity());

    expect(fetchMock).not.toHaveBeenCalled();
  });
});
