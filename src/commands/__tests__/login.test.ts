/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { bootstrapConfig } from "../../drivers/env";
import { pluginLoginMap } from "../../plugins/login";
import { mockGetDoc } from "../../testing/firestore";
import { login } from "../login";
import { signInWithCredential } from "firebase/auth";
import { readFile, writeFile } from "fs/promises";

jest.spyOn(Date, "now").mockReturnValue(1.6e12);
jest.mock("fs/promises");
jest.mock("../../drivers/auth/path", () => ({
  getIdentityFilePath: jest.fn(() => "/dummy/identity/file/path"),
}));
jest.mock("../../drivers/config", () => ({
  ...jest.requireActual("../../drivers/config"),
  saveConfig: jest.fn(),
  loadConfig: jest.fn(() => bootstrapConfig),
}));
jest.mock("../../drivers/stdio");
jest.mock("../../plugins/login");

const mockSignInWithCredential = signInWithCredential as jest.Mock;
const mockReadFile = readFile as jest.Mock;
const mockWriteFile = writeFile as jest.Mock;

describe("login", () => {
  it("prints a friendly error if the org is not found", async () => {
    mockGetDoc(undefined);
    await expect(login({ org: "test-org" })).rejects.toMatchInlineSnapshot(
      `"Could not find organization"`
    );
  });

  it("should print a friendly error if unsupported login", async () => {
    mockGetDoc({
      slug: "test-org",
      tenantId: "test-tenant",
      ssoProvider: "microsoft",
    });
    await expect(login({ org: "test-org" })).rejects.toMatchInlineSnapshot(
      `"Unsupported login for your organization"`
    );
  });

  describe("organization exists", () => {
    let credentialData: string = "";

    beforeEach(() => {
      credentialData = "";
      jest.clearAllMocks();

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
            },
          })
      );

      mockGetDoc({
        slug: "test-org",
        tenantId: "test-tenant",
        ssoProvider: "google",
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
      expect((signInWithCredential as jest.Mock).mock.calls).toMatchSnapshot();
    });

    it("returns an error message if firebase cannot determine the user's email", async () => {
      mockSignInWithCredential.mockResolvedValueOnce({
        user: {},
      });
      await expect(login({ org: "test-org" })).rejects.toMatchInlineSnapshot(`
"Can not sign in: this user has previously signed in with a different identity provider.
Please contact support@p0.dev to enable this user."
`);
    });
  });

  describe("identity file does not exist", () => {
    beforeEach(() => {
      jest.clearAllMocks();

      // Mock `readFile` to throw an "ENOENT" error
      mockReadFile.mockImplementation(() => {
        const error = new Error("File not found");
        (error as any).code = "ENOENT";
        return Promise.reject(error);
      });

      mockGetDoc({
        slug: "test-org",
        tenantId: "test-tenant",
        ssoProvider: "google",
      });
    });

    it("it should ask user to log in", async () => {
      await expect(login({ org: "test-org" })).rejects.toMatchInlineSnapshot(
        `"Please run \`p0 login <organization>\` to use the P0 CLI."`
      );
    });
  });
});
