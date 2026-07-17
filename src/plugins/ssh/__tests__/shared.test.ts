/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { isSudoCommand } from "../shared";
import { describe, expect, it } from "vitest";

describe("isSudoCommand", () => {
  it("is true for the --sudo flag", () => {
    expect(isSudoCommand({ sudo: true })).toBe(true);
  });

  it("is true when the remote command is sudo", () => {
    expect(isSudoCommand({ command: "sudo" })).toBe(true);
  });

  it("is false otherwise", () => {
    expect(isSudoCommand({ command: "ls" })).toBeFalsy();
  });
});
