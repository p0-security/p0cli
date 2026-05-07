/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { assumeRoleWithSaml } from "../assumeRole";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../common/fetch", () => ({
  validateResponse: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../../common/xml", () => ({
  parseXml: vi.fn(() => ({
    AssumeRoleWithSAMLResponse: {
      AssumeRoleWithSAMLResult: {
        Credentials: {
          AccessKeyId: "AKIAEXAMPLE",
          SecretAccessKey: "secret",
          SessionToken: "session",
        },
      },
    },
  })),
}));

describe("assumeRoleWithSaml()", () => {
  const fetchMock = vi.fn();

  const baseArgs = {
    account: "123456789012",
    role: "MyRole",
    saml: { providerName: "okta", response: "base64-saml" },
  };

  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockResolvedValue({
      ok: true,
      text: () => Promise.resolve("<xml/>"),
    } as unknown as Response);
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const captureCall = () => {
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    const params = Object.fromEntries(
      new URLSearchParams((init as RequestInit).body as string)
    );
    return { url: url as string, params };
  };

  it("uses the commercial partition by default", async () => {
    await assumeRoleWithSaml(baseArgs);

    const { url, params } = captureCall();
    expect(url).toBe("https://sts.us-east-1.amazonaws.com");
    expect(params.RoleArn).toBe("arn:aws:iam::123456789012:role/MyRole");
    expect(params.PrincipalArn).toBe(
      "arn:aws:iam::123456789012:saml-provider/okta"
    );
    expect(params.SAMLAssertion).toBe("base64-saml");
  });

  it("targets GovCloud STS and emits aws-us-gov ARNs", async () => {
    await assumeRoleWithSaml({
      ...baseArgs,
      account: "145302212528",
      partition: "aws-us-gov",
      role: "p0-grants/P0GrantsRole12",
      saml: { providerName: "P0GovStg", response: "base64-saml" },
    });

    const { url, params } = captureCall();
    expect(url).toBe("https://sts.us-gov-west-1.amazonaws.com");
    expect(params.RoleArn).toBe(
      "arn:aws-us-gov:iam::145302212528:role/p0-grants/P0GrantsRole12"
    );
    expect(params.PrincipalArn).toBe(
      "arn:aws-us-gov:iam::145302212528:saml-provider/P0GovStg"
    );
  });
});
