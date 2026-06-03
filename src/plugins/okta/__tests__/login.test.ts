/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  getClientId,
  getProviderDomain,
  getProviderType,
} from "../../../types/authUtils";
import { Identity } from "../../../types/identity";
import { OrgData } from "../../../types/org";
import { AwsFederatedLogin } from "../../aws/types";
import { oidcLogin, oidcLoginSteps } from "../../oidc/login";
import { fetchSamlAssertionForAws, oktaLogin } from "../login";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../types/authUtils");
vi.mock("../../oidc/login");
vi.mock("../../../drivers/auth");
vi.mock("../../../drivers/stdio");

const mockIdentity = {
  org: {},
  credential: {
    access_token: "mock-access-token",
    id_token: "mock-id-token",
    expires_at: Date.now() + 3600000,
  },
} as unknown as Identity;

const mockConfig: AwsFederatedLogin = {
  type: "federated",
  provider: {
    type: "okta",
    appId: "mock-app-id",
    identityProvider: "mock-idp",
    method: { type: "saml" },
  },
};

describe("fetchSsoWebToken", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getProviderType).mockReturnValue("okta");
    vi.mocked(getProviderDomain).mockReturnValue("example.okta.com");
    vi.mocked(getClientId).mockReturnValue("mock-client-id");
  });

  it("does not read response body twice on 400 with non-invalid_grant error", async () => {
    const mockJson = vi.fn().mockResolvedValue({
      error: "access_denied",
      error_description: "Access to this application is denied.",
    });
    const mockText = vi.fn();

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        statusText: "Bad Request",
        url: "https://example.okta.com/oauth2/v1/token",
        json: mockJson,
        text: mockText,
      })
    );

    await expect(
      fetchSamlAssertionForAws(mockIdentity, mockConfig)
    ).rejects.toThrow("400 Bad Request");

    expect(mockJson).toHaveBeenCalledOnce();
    expect(mockText).not.toHaveBeenCalled();
  });
});

describe("oktaLogin scope handling", () => {
  const mockOrg = { slug: "test-org" } as unknown as OrgData;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getProviderType).mockReturnValue("okta");
    vi.mocked(getProviderDomain).mockReturnValue("example.okta.com");
    vi.mocked(getClientId).mockReturnValue("mock-client-id");
    // oidcLoginSteps is shape-only here; we only need a non-null return so
    // that oidcLogin gets called. The mock for oidcLogin is the assertion target.
    vi.mocked(oidcLoginSteps).mockReturnValue({} as any);
  });

  it("requests offline_access on the first attempt", async () => {
    vi.mocked(oidcLogin).mockResolvedValue({
      access_token: "at",
      id_token: "id",
      refresh_token: "rt",
      expires_in: 3600,
      expiry: "x",
    } as any);

    await oktaLogin(mockOrg);

    expect(oidcLoginSteps).toHaveBeenCalledOnce();
    const [, scope] = vi.mocked(oidcLoginSteps).mock.calls[0]!;
    expect(scope).toContain("offline_access");
  });

  it("retries without offline_access on invalid_scope", async () => {
    vi.mocked(oidcLogin)
      .mockRejectedValueOnce(
        new Error(
          'Error in fetch request to .../device/authorize\n400\n\n{"error":"invalid_scope"}'
        )
      )
      .mockResolvedValueOnce({
        access_token: "at",
        id_token: "id",
        expires_in: 3600,
        expiry: "x",
      } as any);

    await oktaLogin(mockOrg);

    expect(oidcLoginSteps).toHaveBeenCalledTimes(2);
    const firstScope = vi.mocked(oidcLoginSteps).mock.calls[0]![1];
    const secondScope = vi.mocked(oidcLoginSteps).mock.calls[1]![1];
    expect(firstScope).toContain("offline_access");
    expect(secondScope).not.toContain("offline_access");
  });

  it("propagates non-invalid_scope errors without retry", async () => {
    vi.mocked(oidcLogin).mockRejectedValue(
      new Error("some other auth failure")
    );

    await expect(oktaLogin(mockOrg)).rejects.toThrow("some other auth failure");
    expect(oidcLoginSteps).toHaveBeenCalledOnce();
  });
});
