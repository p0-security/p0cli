/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { awsCommand } from "..";
import { fetchIntegrationConfig } from "../../../drivers/api";
import { print1, print2 } from "../../../drivers/stdio";
import { failure } from "../../../testing/yargs";
import { samlResponse } from "./__input__/saml-response";
import { stsResponse } from "./__input__/sts-response";
import { beforeEach, describe, expect, it, vi, Mock } from "vitest";
import yargs from "yargs";

vi.mock("fs/promises");
vi.mock("../../../drivers/auth");
vi.mock("../../../drivers/stdio");
vi.mock("../../../drivers/api");
vi.mock("typescript", async (importOriginal) => ({
  ...(await importOriginal<typeof import("typescript")>()),
  sys: {
    writeOutputIsTTY: () => true,
  },
}));
vi.mock("../../shared/request", () => ({
  provisionRequest: vi.fn(),
}));
vi.mock("../../../util", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../util")>()),
  getAppName: () => "p0",
}));

const mockFetch = vi.spyOn(global, "fetch");
const mockPrint1 = print1 as Mock;
const mockPrint2 = print2 as Mock;
const mockIntegrationConfigFetch = fetchIntegrationConfig as Mock;

beforeEach(() => {
  vi.clearAllMocks();
  mockFetch.mockImplementation(
    async (url: RequestInfo | URL) =>
      ({
        ok: true,
        // This is the token response from fetchSsoWebToken
        json: async () => ({}),
        // This is the XML response from fetchSamlResponse or stsAssumeRole
        text: async () =>
          (url as string).match(/okta.com/) ? samlResponse : stsResponse,
      }) as Response
  );
});

describe("aws role", () => {
  describe("a single installed account", () => {
    const item = {
      label: "test",
      state: "installed",
    };
    describe("without Okta SAML", () => {
      mockIntegrationConfigFetch.mockResolvedValue({
        config: { "iam-write": { "1": item } },
      });
      describe("assume", () => {
        const command = "aws role assume Role1";
        it("should print a friendly error message", async () => {
          const error = await failure(awsCommand(yargs()), command);
          expect(error).toBe(
            "Account test is not configured for Okta SAML login."
          );
        });
      });
    });
    describe("with Okta SAML", () => {
      beforeEach(() => {
        mockIntegrationConfigFetch.mockResolvedValue({
          config: {
            "iam-write": {
              "1": {
                ...item,
                login: {
                  type: "federated",
                  provider: {
                    type: "okta",
                    appId: "0oabcdefgh",
                    identityProvider: "okta",
                  },
                },
              },
            },
          },
        });
      });
      describe("assume", () => {
        it("should assume a role", async () => {
          await awsCommand(yargs()).parse("aws role assume Role1");
          expect(mockPrint2.mock.calls).toMatchSnapshot("stderr");
          expect(mockPrint1.mock.calls).toMatchSnapshot("stdout");
        });
      });
    });
  });
});
