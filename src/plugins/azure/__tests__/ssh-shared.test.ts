/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../../drivers/stdio";
import { exec } from "../../../util";
import {
  AD_CERT_FILENAME,
  azSshCertCommand,
  generateSshKeyAndAzureAdCert,
} from "../ssh-shared";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../drivers/stdio", () => ({
  print2: vi.fn(),
}));

// Spread the original so the real osSafeCommand (used by azSshCertCommand)
// keeps working; only stub the subprocess execution.
vi.mock("../../../util", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../util")>()),
  exec: vi.fn(),
}));

const mockExec = vi.mocked(exec);
const mockPrint2 = vi.mocked(print2);

const KEY_PATH = path.join("tmp", "p0cli-keys");

beforeEach(() => {
  vi.clearAllMocks();
});

describe("azSshCertCommand", () => {
  it("builds an `az ssh cert` command targeting the cert file in the key path", () => {
    expect(azSshCertCommand(KEY_PATH)).toEqual({
      command: "az",
      args: ["ssh", "cert", "--file", path.join(KEY_PATH, AD_CERT_FILENAME)],
    });
  });
});

describe("generateSshKeyAndAzureAdCert", () => {
  it("executes the cert command with check enabled and prints nothing without debug", async () => {
    mockExec.mockResolvedValue({ stdout: "ok", stderr: "" } as any);

    await generateSshKeyAndAzureAdCert(KEY_PATH);

    expect(mockExec).toHaveBeenCalledWith(
      "az",
      ["ssh", "cert", "--file", path.join(KEY_PATH, AD_CERT_FILENAME)],
      { check: true }
    );
    expect(mockPrint2).not.toHaveBeenCalled();
  });

  it("prints progress and the command output when debug is enabled", async () => {
    mockExec.mockResolvedValue({
      stdout: "generated cert",
      stderr: "some warning",
    } as any);

    await generateSshKeyAndAzureAdCert(KEY_PATH, { debug: true });

    expect(mockPrint2).toHaveBeenCalledWith(
      "Generating Azure AD SSH certificate..."
    );
    expect(mockPrint2).toHaveBeenCalledWith("generated cert");
    expect(mockPrint2).toHaveBeenCalledWith("some warning");
  });

  it("prints the failed command's output and rejects with a descriptive error", async () => {
    mockExec.mockRejectedValue(
      Object.assign(new Error("exited with code 1"), {
        stdout: "az stdout",
        stderr: "az stderr",
      })
    );

    await expect(generateSshKeyAndAzureAdCert(KEY_PATH)).rejects.toMatch(
      /Failed to generate Azure AD SSH certificate: Error: exited with code 1/
    );

    expect(mockPrint2).toHaveBeenCalledWith("az stdout");
    expect(mockPrint2).toHaveBeenCalledWith("az stderr");
  });
});
