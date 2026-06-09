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
import { AwsFederatedLogin } from "../../aws/types";
import { fetchSamlAssertionForAws } from "../login";
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
