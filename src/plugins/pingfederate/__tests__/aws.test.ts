/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { withRedirectServer } from "../../../common/auth/server";
import { fetchIntegrationConfig } from "../../../drivers/api";
import { Authn } from "../../../types/identity";
import { osSafeOpen } from "../../../util";
import { pingFederateSamlSource } from "../aws";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../common/auth/server", () => ({
  withRedirectServer: vi.fn(),
}));
vi.mock("../../../drivers/api", () => ({
  fetchIntegrationConfig: vi.fn(),
}));
vi.mock("../../../drivers/stdio", () => ({ print2: vi.fn() }));
vi.mock("../../../util", () => ({ osSafeOpen: vi.fn() }));

const authn = {
  identity: { org: { slug: "test-org" } },
  userCredential: { user: { email: "Alice@example.com" } },
} as unknown as Authn;

const samlFor = (sourceIdentity: string) =>
  Buffer.from(
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><saml:AttributeStatement><saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/SourceIdentity"><saml:AttributeValue>${sourceIdentity}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`
  ).toString("base64");

/** Runs the sign-in, and posts `form` to the local server */
const signIn = async (form: { SAMLResponse?: string }) => {
  vi.mocked(withRedirectServer).mockImplementation(
    async (beginAuth, completeAuth) => {
      await beginAuth({} as any);
      return await completeAuth(undefined, form);
    }
  );
  return await pingFederateSamlSource.fetch(authn, "pf-prod");
};

describe("pingFederateSamlSource", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(fetchIntegrationConfig).mockResolvedValue({
      config: { app: { "pf-prod": { pingFederateUrl: "https://sso.test/" } } },
    });
  });

  it("starts sign-in at the p0cli ACS index, on the loopback address only", async () => {
    const saml = samlFor("alice@example.com");

    await expect(signIn({ SAMLResponse: saml })).resolves.toBe(saml);

    const url = new URL(vi.mocked(osSafeOpen).mock.calls[0]![0]);
    expect(url.origin + url.pathname).toBe(
      "https://sso.test/idp/startSSO.ping"
    );
    expect(url.searchParams.get("PartnerSpId")).toBe("urn:amazon:webservices");
    expect(url.searchParams.get("ACSIdx")).toBe("1");
    expect(url.searchParams.get("TargetResource")).toMatch(/^[0-9a-f]{64}$/);
    const options = vi.mocked(withRedirectServer).mock.calls[0]![2]!;
    expect(options).toMatchObject({
      host: "127.0.0.1",
      port: 52702,
      post: "/saml",
    });
    const nonce = url.searchParams.get("TargetResource")!;
    expect(options.accepts!({ RelayState: nonce })).toBe(true);
    expect(options.accepts!({ RelayState: "other" })).toBe(false);
  });

  it("refuses a response for another user", async () => {
    await expect(
      signIn({ SAMLResponse: samlFor("mallory@example.com") })
    ).rejects.toBe(
      "PingFederate signed in mallory@example.com, not Alice@example.com."
    );
  });
});
