/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { parseXml } from "../../../common/xml";
import { fetchIntegrationConfig } from "../../../drivers/api";
import { Authn } from "../../../types/identity";
import { assumeRoleWithSaml } from "../../aws/assumeRole";
import { getAwsConfig } from "../../aws/config";
import { assumeRoleWithOktaSaml } from "../aws";
import { fetchSamlAssertionForAws } from "../login";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock dependencies
vi.mock("../../../drivers/auth");
vi.mock("../../../drivers/api", () => ({
  fetchIntegrationConfig: vi.fn(),
}));
vi.mock("../../aws/config", () => ({
  getAwsConfig: vi.fn(),
}));
vi.mock("../../aws/assumeRole", () => ({
  assumeRoleWithSaml: vi.fn(),
}));
vi.mock("../login", () => ({
  fetchSamlAssertionForAws: vi.fn(),
}));
vi.mock("../../../common/xml", () => ({
  parseXml: vi.fn(),
}));
vi.mock("../../../util", () => ({
  sleep: vi.fn().mockResolvedValue(undefined),
}));

describe("assumeRoleWithOktaSaml retry logic", () => {
  const MOCK_ACCOUNT_ID = "1234";

  const mockAuthn: Authn = {
    getToken: vi.fn(),
    identity: { org: { slug: "test-org" } },
  } as unknown as Authn;

  const mockConfig = {
    id: MOCK_ACCOUNT_ID,
    login: {
      type: "federated" as const,
      provider: {
        identityProvider: "test-idp",
      },
    },
  };

  const createMockSamlWithRoles = (
    roles: string[],
    partition: string = "aws"
  ) => ({
    "saml2p:Response": {
      "saml2:Assertion": {
        "saml2:AttributeStatement": {
          "saml2:Attribute": [
            {
              _attributes: {
                Name: "https://aws.amazon.com/SAML/Attributes/Role",
              },
              "saml2:AttributeValue": roles.map(
                (r) =>
                  `arn:${partition}:iam::${MOCK_ACCOUNT_ID}:saml-provider/test,arn:${partition}:iam::${MOCK_ACCOUNT_ID}:role/${r}`
              ),
            },
          ],
        },
      },
    },
  });

  beforeEach(() => {
    vi.clearAllMocks();

    vi.mocked(getAwsConfig).mockResolvedValue({
      identity: {} as any,
      config: mockConfig as any,
    });
    vi.mocked(fetchSamlAssertionForAws).mockResolvedValue("base64-saml");
    vi.mocked(assumeRoleWithSaml).mockResolvedValue({
      AWS_ACCESS_KEY_ID: "key",
      AWS_SECRET_ACCESS_KEY: "secret",
      AWS_SESSION_TOKEN: "token",
      AWS_SECURITY_TOKEN: "token",
    });
  });

  it("should succeed when role is available", async () => {
    vi.mocked(parseXml).mockReturnValue(
      createMockSamlWithRoles(["p0-grants/P0GrantsRole1"])
    );

    const result = await assumeRoleWithOktaSaml(
      mockAuthn,
      { role: "p0-grants/P0GrantsRole1" },
      false
    );

    expect(result).toBeDefined();
    expect(fetchSamlAssertionForAws).toHaveBeenCalledTimes(1);
    expect(parseXml).toHaveBeenCalledTimes(1);
  });

  it("should retry when role is not available, then succeed", async () => {
    vi.mocked(parseXml)
      .mockReturnValueOnce(createMockSamlWithRoles(["p0-grants/P0GrantsRole1"]))
      .mockReturnValueOnce(
        createMockSamlWithRoles([
          "p0-grants/P0GrantsRole1",
          "p0-grants/P0GrantsRole16", // Second call: role becomes available
        ])
      );

    const result = await assumeRoleWithOktaSaml(
      mockAuthn,
      { role: "p0-grants/P0GrantsRole16" },
      false
    );

    expect(result).toBeDefined();
    expect(fetchSamlAssertionForAws).toHaveBeenCalledTimes(2);
    expect(parseXml).toHaveBeenCalledTimes(2);
  });

  it("should pass the commercial partition to assumeRoleWithSaml", async () => {
    vi.mocked(parseXml).mockReturnValue(
      createMockSamlWithRoles(["p0-grants/P0GrantsRole1"], "aws")
    );

    await assumeRoleWithOktaSaml(
      mockAuthn,
      { role: "p0-grants/P0GrantsRole1" },
      false
    );

    expect(assumeRoleWithSaml).toHaveBeenCalledWith(
      expect.objectContaining({ partition: "aws" })
    );
  });

  it("should detect the GovCloud partition from the SAML and pass it through", async () => {
    vi.mocked(parseXml).mockReturnValue(
      createMockSamlWithRoles(["p0-grants/P0GrantsRole12"], "aws-us-gov")
    );

    const result = await assumeRoleWithOktaSaml(
      mockAuthn,
      { role: "p0-grants/P0GrantsRole12" },
      false
    );

    expect(result).toBeDefined();
    expect(assumeRoleWithSaml).toHaveBeenCalledWith(
      expect.objectContaining({
        account: MOCK_ACCOUNT_ID,
        partition: "aws-us-gov",
        role: "p0-grants/P0GrantsRole12",
      })
    );
  });
});

describe("assumeRoleWithOktaSaml federation app", () => {
  const mockAuthn = {
    identity: { org: { slug: "test-org" } },
  } as unknown as Authn;

  const useLogin = (login: object) =>
    vi.mocked(getAwsConfig).mockResolvedValue({
      identity: {} as any,
      config: { id: "1234", login } as any,
    });

  const useFederation = (provider: object) =>
    vi.mocked(fetchIntegrationConfig).mockResolvedValue({
      config: { federation: { "okta-prod": { provider, state: "installed" } } },
    });

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(fetchSamlAssertionForAws).mockResolvedValue("base64-saml");
    vi.mocked(parseXml).mockReturnValue({
      "saml2p:Response": {
        "saml2:Assertion": {
          "saml2:AttributeStatement": {
            "saml2:Attribute": [
              {
                _attributes: {
                  Name: "https://aws.amazon.com/SAML/Attributes/Role",
                },
                "saml2:AttributeValue": [
                  "arn:aws:iam::1234:saml-provider/okta-saml,arn:aws:iam::1234:role/Admin",
                ],
              },
            ],
          },
        },
      },
    });
  });

  it("uses the app ID of the federation item and the SAML provider of the login", async () => {
    useLogin({
      type: "federated",
      federation: "okta-prod",
      samlProvider: "okta-saml",
    });
    useFederation({ type: "okta", appId: "0oa123" });

    await assumeRoleWithOktaSaml(mockAuthn, { role: "Admin" }, false);

    expect(fetchIntegrationConfig).toHaveBeenCalledWith(
      mockAuthn,
      "aws-federation",
      false
    );
    expect(fetchSamlAssertionForAws).toHaveBeenCalledWith(
      expect.anything(),
      "0oa123",
      false
    );
    expect(assumeRoleWithSaml).toHaveBeenCalledWith(
      expect.objectContaining({
        saml: { providerName: "okta-saml", response: "base64-saml" },
      })
    );
  });

  it("uses the inline provider of a login without a federation item", async () => {
    useLogin({
      type: "federated",
      provider: { type: "okta", appId: "0oa456", identityProvider: "legacy" },
    });

    await assumeRoleWithOktaSaml(mockAuthn, { role: "Admin" }, false);

    expect(fetchIntegrationConfig).not.toHaveBeenCalled();
    expect(fetchSamlAssertionForAws).toHaveBeenCalledWith(
      expect.anything(),
      "0oa456",
      false
    );
    expect(assumeRoleWithSaml).toHaveBeenCalledWith(
      expect.objectContaining({
        saml: { providerName: "legacy", response: "base64-saml" },
      })
    );
  });

  it("rejects a federation item that is not an Okta app", async () => {
    useLogin({
      type: "federated",
      federation: "okta-prod",
      samlProvider: "okta-saml",
    });
    useFederation({ type: "pingone" });

    await expect(
      assumeRoleWithOktaSaml(mockAuthn, { role: "Admin" }, false)
    ).rejects.toBe("Federation app okta-prod is not an Okta app.");
  });
});
