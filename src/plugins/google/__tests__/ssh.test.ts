/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { gcpSshProvider } from "../ssh";
import { describe, expect, it } from "vitest";

describe("unprovisionedAccessPatterns", () => {
  const matches = (stderr: string) =>
    gcpSshProvider.unprovisionedAccessPatterns.some((p) =>
      p.pattern.test(stderr)
    );

  it("retries on a key rejection while OS Login access propagates", () => {
    expect(matches("Permission denied (publickey).")).toBe(true);
  });

  it("retries on a key rejection when the host's sshd offers other auth methods", () => {
    // sshd lists every enabled auth method, so a VM that also allows password
    // (or keyboard-interactive) auth reports more than just (publickey).
    expect(
      matches("alice@10.0.0.4: Permission denied (publickey,password).")
    ).toBe(true);
  });
});
