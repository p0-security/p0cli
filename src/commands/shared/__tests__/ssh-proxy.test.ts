/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { setOrg } from "../../ssh-proxy";
import { SshProxyCommandArgs } from "../ssh";
import { beforeEach, describe, expect, it, vi } from "vitest";
import yargs from "yargs";

vi.mock("../../../drivers/stdio", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../drivers/stdio")>()),
  print2: vi.fn(),
}));

describe("setOrg", () => {
  const baseArgs = {
    $0: "p0",
    _: ["ssh-proxy"],
    destination: "my-instance",
    port: "22",
    provider: "aws",
    requestJson: "/tmp/request.json",
    identityFile: "/tmp/key",
  } satisfies yargs.ArgumentsCamelCase<SshProxyCommandArgs>;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.P0_ORG;
  });

  it("does not set P0_ORG when args.org is undefined", () => {
    setOrg({ ...baseArgs, org: undefined });
    expect(process.env.P0_ORG).toBeUndefined();
  });

  it("sets P0_ORG when args.org is provided", () => {
    setOrg({ ...baseArgs, org: "my-org" });
    expect(process.env.P0_ORG).toBe("my-org");
  });
});
