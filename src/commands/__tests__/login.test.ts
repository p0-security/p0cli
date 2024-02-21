import { pluginLoginMap } from "../../plugins/login";
import { mockGetDoc } from "../../testing/firestore";
import { login } from "../login";
import { signInWithCredential } from "firebase/auth";
import { readFile, writeFile } from "fs/promises";

jest.spyOn(Date, "now").mockReturnValue(1.6e12);
jest.mock("fs/promises");
jest.mock("../../drivers/auth", () => ({
  ...jest.requireActual("../../drivers/auth"),
  IDENTITY_FILE_PATH: "/path/to/home/.p0",
}));
jest.mock("../../drivers/stdio");
jest.mock("../../plugins/login");

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
    mockReadFile.mockImplementation(async () =>
      Buffer.from(credentialData, "utf-8")
    );
    mockWriteFile.mockImplementation(async (_path, data) => {
      credentialData = data;
    });
    beforeEach(() => {
      credentialData = "";
      jest.clearAllMocks();
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
    it("should write the user's identity to the file system", async () => {
      await login({ org: "test-org" });
      expect(mockWriteFile.mock.calls).toMatchSnapshot();
    });
    it("validates authentication", async () => {
      await login({ org: "test-org" });
      expect((signInWithCredential as jest.Mock).mock.calls).toMatchSnapshot();
    });
  });
});
