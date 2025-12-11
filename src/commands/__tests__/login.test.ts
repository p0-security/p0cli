/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchOrgData } from "../../drivers/api";
import * as auth from "../../drivers/auth";
import * as config from "../../drivers/config";
import { defaultConfig } from "../../drivers/env";
import { print2 } from "../../drivers/stdio";
import { pluginLoginMap } from "../../plugins/login";
import { Identity } from "../../types/identity";
import { login } from "../login";
import { signInWithCredential } from "firebase/auth";
import { readFile, writeFile } from "fs/promises";
import { beforeEach, describe, expect, it, vi, Mock } from "vitest";

vi.spyOn(Date, "now").mockReturnValue(1.6e12);
vi.mock("fs/promises");
vi.mock("../../drivers/auth/path", () => ({
  getIdentityFilePath: vi.fn(() => "/dummy/identity/file/path"),
}));
vi.mock("../../drivers/stdio");
vi.mock("../../plugins/login");
vi.mock("../../drivers/api");
vi.mock("../../util", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../util")>()),
  getAppName: () => "p0",
}));
vi.mock("firebase/auth", async (importOriginal) => {
  const actual = await importOriginal<typeof import("firebase/auth")>();

  const mockFirebaseAuth = {
    tenantId: "test-tenant",
    apiKey: "test-api-key",
    appName: "test-app",
    authDomain: "test.firebaseapp.com",
  };

  const mockFirebaseCredential = {
    providerId: "google.com",
    signInMethod: "google.com",
    accessToken: "test-access-token",
    idToken: "test-id-token",
  };

  return {
    ...actual,
    signInWithCredential: vi.fn(),
    OAuthProvider: vi.fn().mockImplementation(() => ({
      credential: vi.fn().mockReturnValue(mockFirebaseCredential),
    })),
    getAuth: vi.fn().mockReturnValue(mockFirebaseAuth),
    initializeAuth: vi.fn().mockReturnValue(mockFirebaseAuth),
  };
});

const mockIdentity: Identity = {
  // @ts-expect-error credential has more fields, this is enough for tests
  credential: {
    expires_at: Date.now() * 1e-3 + 60 * 1000,
  },
  // @ts-expect-error org has more fields, this is enough for tests
  org: {
    tenantId: "test-tenant",
    slug: "test-org",
    auth: {
      type: "sso",
      provider: {
        ssoProvider: "google",
      },
    },
  },
  token: "test",
};

const mockSignInWithCredential = signInWithCredential as Mock;
const mockReadFile = readFile as Mock;
const mockWriteFile = writeFile as Mock;
const mockFetchOrgData = fetchOrgData as Mock;

describe("login", () => {
  beforeEach(() => {
    vi.spyOn(config, "loadConfig").mockResolvedValueOnce(defaultConfig);
    vi.spyOn(config, "saveConfig").mockImplementation(vi.fn());
    vi.spyOn(config, "getTenantConfig").mockReturnValue(defaultConfig);
    // do NOT spyOn getContactMessage — you want the real one
  });

  it("prints a friendly error if the org is not provided", async () => {
    await expect(login({} as any)).rejects.toMatchInlineSnapshot(
      `"The organization ID is required. Please provide it as an argument or set the P0_ORG environment variable."`
    );
  });

  it("prints a friendly error if the org is not found", async () => {
    mockFetchOrgData.mockImplementation(() => {
      throw "Not found";
    });
    await expect(login({ org: "test-org" })).rejects.toMatchInlineSnapshot(
      `"Could not find organization"`
    );
  });

  it("prints a friendly error if unsupported login", async () => {
    mockFetchOrgData.mockResolvedValue({
      slug: "test-org",
      tenantId: "test-tenant",
      auth: {
        type: "sso",
        provider: {
          ssoProvider: "microsoft",
        },
      },
    });
    await expect(login({ org: "test-org" })).rejects.toMatchInlineSnapshot(
      `"Unsupported login for your organization"`
    );
  });

  describe("identity file does not exist", () => {
    beforeEach(() => {
      vi.clearAllMocks();

      // Mock `readFile` to throw an "ENOENT" error
      mockReadFile.mockImplementation(() => {
        const error = new Error("File not found");
        (error as any).code = "ENOENT";
        return Promise.reject(error);
      });
      mockFetchOrgData.mockResolvedValue({
        slug: "test-org",
        tenantId: "test-tenant",
        auth: {
          type: "sso",
          provider: {
            ssoProvider: "google",
          },
        },
      });
    });

    it("it should ask user to log in", async () => {
      await expect(login({ org: "test-org" })).rejects.toMatchInlineSnapshot(
        `"Please run \`p0 login <organization>\`."`
      );
    });
  });

  describe("organization exists", () => {
    let credentialData: string = "";

    beforeEach(() => {
      credentialData = "";
      vi.clearAllMocks();
      vi.spyOn(config, "loadConfig").mockResolvedValueOnce(defaultConfig);
      mockReadFile.mockImplementation(async () =>
        Buffer.from(credentialData, "utf-8")
      );
      mockWriteFile.mockImplementation(async (_path, data) => {
        credentialData = data;
      });
      mockSignInWithCredential.mockImplementation(
        async (_auth, _firebaseCredential) =>
          Promise.resolve({
            user: {
              email: "user@p0.dev",
              getIdToken: vi.fn().mockResolvedValue("mock-id-token"),
            },
          })
      );
      mockFetchOrgData.mockResolvedValue({
        slug: "test-org",
        tenantId: "test-tenant",
        auth: {
          type: "sso",
          provider: {
            ssoProvider: "google",
          },
        },
      });
    });

    it("should call the provider's login function", async () => {
      await login({ org: "test-org" });
      expect(pluginLoginMap.google).toHaveBeenCalled();
    });

    it("should write the user's identity & config to the file system", async () => {
      await login({ org: "test-org" });
      expect(mockWriteFile.mock.calls).toMatchSnapshot();
    });

    it("validates authentication", async () => {
      await login({ org: "test-org" });
      expect((signInWithCredential as Mock).mock.calls).toMatchSnapshot();
    });

    it("returns an error message if firebase cannot determine the user email", async () => {
      mockSignInWithCredential.mockResolvedValueOnce({
        user: {},
      });
      await expect(login({ org: "test-org" })).rejects.toMatchInlineSnapshot(`
"Can not sign in: this user has previously signed in with a different identity provider.
Please contact support@p0.dev for assistance."
`);
    });

    describe("already logged in", () => {
      beforeEach(() => {
        vi.clearAllMocks();

        // Mock credentials file on disk (needed for loadCredentials to read existing identity)
        mockReadFile.mockResolvedValue(
          Buffer.from(JSON.stringify(mockIdentity), "utf-8")
        );
        // Mock Firebase re-authentication (needed when login is called with --refresh or different org)
        mockSignInWithCredential.mockImplementation(
          async (_auth, _firebaseCredential) =>
            Promise.resolve({
              user: {
                email: "user@p0.dev",
                getIdToken: vi.fn().mockResolvedValue("mock-id-token"),
              },
            })
        );
        vi.spyOn(auth, "loadCredentials").mockResolvedValue(mockIdentity);
        mockFetchOrgData.mockResolvedValue({
          slug: "test-org",
          tenantId: "test-tenant",
          auth: {
            type: "sso",
            provider: {
              ssoProvider: "google",
            },
          },
        });
      });

      it("no org provided, prints current logged-in status", async () => {
        await login({} as any);

        expect(print2).toHaveBeenCalledWith(
          "You are currently logged in to the test-org organization."
        );

        expect(print2).toHaveBeenCalledWith(
          expect.stringContaining("The current session expires in ")
        );
      });

      it("org provided, prints already logged-in status", async () => {
        await login({ org: "test-org" });

        expect(print2).toHaveBeenCalledWith(
          "You are currently logged in to the test-org organization."
        );

        expect(print2).toHaveBeenCalledWith(
          expect.stringContaining("The current session expires in ")
        );
      });

      it("--refresh provided, need to re-login", async () => {
        await login({ org: "test-org", refresh: true });

        expect(print2).toHaveBeenCalledWith(
          "You are now logged in to the test-org organization, and can use the p0 CLI."
        );
      });

      it("different org provided, need to re-login", async () => {
        mockFetchOrgData.mockResolvedValue({
          slug: "other-org",
          tenantId: "other-tenant",
          auth: {
            type: "sso",
            provider: {
              ssoProvider: "google",
            },
          },
        });

        await login({ org: "other-org" });

        expect(print2).toHaveBeenCalledWith(
          "You are now logged in to the other-org organization, and can use the p0 CLI."
        );
      });
    });
  });
});
