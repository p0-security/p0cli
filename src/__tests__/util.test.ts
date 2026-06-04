/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { detectShell, newShellFormatter } from "../util";
import { describe, expect, it } from "vitest";

const asEnv = (env: Record<string, string>) => env as NodeJS.ProcessEnv;

describe("detectShell", () => {
  it("treats every common POSIX shell as posix", () => {
    for (const shell of [
      "/bin/bash",
      "/usr/bin/bash",
      "/usr/bin/zsh",
      "/bin/zsh",
      "/bin/sh",
      "/bin/dash",
      "/usr/bin/ksh",
      "/usr/bin/bash", // git-bash on Windows reports this
    ]) {
      expect(detectShell(asEnv({ SHELL: shell }))).toBe("posix");
    }
  });

  it("detects fish only on an exact basename match (no false positives)", () => {
    expect(detectShell(asEnv({ SHELL: "/usr/bin/fish" }))).toBe("fish");
    expect(detectShell(asEnv({ SHELL: "/opt/homebrew/bin/fish" }))).toBe(
      "fish"
    );
    // A shell whose name merely contains "fish" must NOT be misclassified.
    expect(detectShell(asEnv({ SHELL: "/bin/myfishshell" }))).toBe("posix");
    expect(detectShell(asEnv({ SHELL: "/bin/swordfish" }))).toBe("posix");
  });

  it("defaults to posix when SHELL is unset", () => {
    expect(detectShell(asEnv({}))).toBe("posix");
  });
});

describe("posix formatter (env assignments/references remain byte-identical to legacy output)", () => {
  const f = newShellFormatter("posix");

  it("emits the legacy `export KEY=value` assignment", () => {
    expect(f.formatEnvAssignment("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")).toBe(
      "export AWS_ACCESS_KEY_ID=AKIAEXAMPLE"
    );
  });

  it('emits the legacy quoted `export KEY="value"` for secrets', () => {
    expect(
      f.formatEnvAssignment("PGPASSWORD", "p@ss w0rd!", { quote: true })
    ).toBe('export PGPASSWORD="p@ss w0rd!"');
  });

  it("emits the legacy `${KEY}` reference", () => {
    expect(f.formatEnvReference("RDS_HOST")).toBe("${RDS_HOST}");
  });

  it("wraps command substitution in eval so multiline output runs line-by-line", () => {
    expect(f.formatEvalCommand("p0 aws role assume Role1")).toBe(
      'eval "$(p0 aws role assume Role1)"'
    );
  });
});

describe("fish formatter", () => {
  const f = newShellFormatter("fish");

  it("uses `set -gx` and `| source`", () => {
    expect(f.formatEnvAssignment("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")).toBe(
      "set -gx AWS_ACCESS_KEY_ID AKIAEXAMPLE"
    );
    expect(
      f.formatEnvAssignment("PGPASSWORD", "p@ss w0rd!", { quote: true })
    ).toBe('set -gx PGPASSWORD "p@ss w0rd!"');
    expect(f.formatEnvReference("RDS_HOST")).toBe("$RDS_HOST");
    expect(f.formatEvalCommand("p0 aws role assume Role1")).toBe(
      "p0 aws role assume Role1 | source"
    );
  });
});
