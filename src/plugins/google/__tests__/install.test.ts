/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { GcpSshInstall } from "../install";
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";

const packageCommand = GcpSshInstall.gcloud.commands.darwin.find((command) =>
  command.startsWith("package=")
);

const runPackageCommand = (architecture: string): string => {
  if (!packageCommand) {
    throw new Error("GCloud install package command is missing");
  }

  return execFileSync(
    "bash",
    [
      "-c",
      `architecture=${architecture}; ${packageCommand}; printf "%s" "$package"`,
    ],
    { encoding: "utf8" }
  );
};

describe("GcpSshInstall", () => {
  it("selects the arm64 GCloud package on Apple Silicon", () => {
    expect(runPackageCommand("arm64")).toBe(
      "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-darwin-arm.tar.gz"
    );
  });

  it("selects the x86_64 GCloud package on Intel Macs", () => {
    expect(runPackageCommand("i386")).toBe(
      "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-darwin-x86_64.tar.gz"
    );
  });
});
