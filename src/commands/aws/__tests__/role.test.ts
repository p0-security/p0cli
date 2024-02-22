import { awsCommand } from "..";
import { print1, print2 } from "../../../drivers/stdio";
import { mockGetDoc } from "../../../testing/firestore";
import { failure } from "../../../testing/yargs";
import { samlResponse } from "./__input__/saml-response";
import { stsResponse } from "./__input__/sts-response";
import yargs from "yargs";

jest.mock("fs/promises");
jest.mock("../../../drivers/auth");
jest.mock("../../../drivers/stdio");
jest.mock("typescript", () => ({
  ...jest.requireActual("typescript"),
  sys: {
    writeOutputIsTTY: () => true,
  },
}));

const mockFetch = jest.spyOn(global, "fetch");
const mockPrint1 = print1 as jest.Mock;
const mockPrint2 = print2 as jest.Mock;

beforeEach(() => {
  jest.clearAllMocks();
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
      account: {
        id: "1",
        description: "1 (test)",
      },
      state: "installed",
    };
    describe("without Okta SAML", () => {
      mockGetDoc({ workflows: { items: [item] } });
      describe.each([
        ["ls", "aws role ls"],
        ["assume", "aws role assume Role1"],
      ])("%s", (_, command) => {
        it("should print a friendly error message", async () => {
          const error = await failure(awsCommand(yargs()), command);
          expect(error).toMatchInlineSnapshot(
            `"Account 1 (test) is not configured for Okta SAML login."`
          );
        });
      });
    });
    describe("with Okta SAML", () => {
      beforeEach(() => {
        mockGetDoc({
          workflows: {
            items: [{ ...item, uidLocation: { id: "okta_saml_sso" } }],
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
      describe("ls", () => {
        it("lists roles", async () => {
          await awsCommand(yargs()).parse("aws role ls");
          expect(mockPrint2.mock.calls).toMatchSnapshot("stderr");
          expect(mockPrint1.mock.calls).toMatchSnapshot("stdout");
        });
      });
    });
  });
});
