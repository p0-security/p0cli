/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  azSshExtensionRemediation,
  classifyAzureCertGenerationError,
} from "../cert-error";
import { describe, expect, it } from "vitest";

// Sample output captured from real `az ssh cert` failures. The Azure CLI
// writes its WARNING/ERROR lines to stderr, but the classifier receives the
// combined output, so the samples are representative of either stream.

/** The `ssh` extension is missing and the Azure CLI's non-interactive dynamic
 * install of it fails at the pip step (observed e.g. in restricted
 * environments where the CLI cannot write to its own extension directory). */
const AUTO_INSTALL_PIP_FAILURE = `
WARNING: The command requires the extension ssh. It will be installed first.
ERROR: An error occurred. Pip failed with status code 1. Use --debug for more information.
`;

/** The same pip failure, but from an interactive session where the Azure CLI
 * prompts before installing the extension. */
const INTERACTIVE_INSTALL_PIP_FAILURE = `
The command requires the extension ssh. Do you want to install it now? The command will continue to run after the extension is installed. (Y/n): Y
Run 'az config set extension.use_dynamic_install=yes_without_prompt' to allow installing extensions without prompt.
An error occurred. Pip failed with status code 1. Use --debug for more information.
`;

/** Dynamic extension install is disabled (extension.use_dynamic_install=no),
 * so the `ssh` command group does not resolve at all. */
const DYNAMIC_INSTALL_DISABLED = `
ERROR: az ssh: 'ssh' is misspelled or not recognized by the system.
`;

/** Older Azure CLI versions without dynamic install report the missing
 * command group differently. */
const COMMAND_GROUP_MISSING = `
ERROR: az: 'ssh' is not in the 'az' command group. See 'az --help'.
`;

/** The extension auto-install succeeded (the WARNING alone is benign) and the
 * command then failed for an unrelated reason. Blaming the extension here
 * would be a misattribution, so this must fall through to the raw error. */
const INSTALL_SUCCEEDED_THEN_LOGIN_FAILURE = `
WARNING: The command requires the extension ssh. It will be installed first.
ERROR: Please run 'az login' to setup account.
`;

/** An unrelated failure with no extension involvement at all. */
const LOGIN_FAILURE = `
ERROR: Please run 'az login' to setup account.
`;

/** The extension is installed but its bundled native dependencies were built
 * for a different Python, e.g. after brew upgraded azure-cli (observed with
 * azure-cli 2.89.0 / Python 3.14 and a stale rpds wheel). */
const EXTENSION_IMPORT_FAILURE = `
ERROR: The command failed with an unexpected error. Here is the traceback:
ERROR: No module named 'rpds.rpds'
Traceback (most recent call last):
  File "/opt/homebrew/Cellar/azure-cli/2.89.0/libexec/lib/python3.14/site-packages/knack/cli.py", line 233, in invoke
    cmd_result = self.invocation.execute(args)
  File "/Users/p0user/.azure/cliextensions/ssh/azext_ssh/custom.py", line 20, in <module>
    from . import rdp_utils
  File "/Users/p0user/.azure/cliextensions/ssh/rpds/__init__.py", line 1, in <module>
    from .rpds import *
ModuleNotFoundError: No module named 'rpds.rpds'
`;

/** A ModuleNotFoundError raised purely from the Azure CLI core, with no
 * frames in the ssh extension: reinstalling the extension would not help. */
const CORE_IMPORT_FAILURE = `
ERROR: The command failed with an unexpected error. Here is the traceback:
ERROR: No module named 'azure.mgmt.core'
Traceback (most recent call last):
  File "/opt/homebrew/Cellar/azure-cli/2.89.0/libexec/lib/python3.14/site-packages/knack/cli.py", line 233, in invoke
    cmd_result = self.invocation.execute(args)
ModuleNotFoundError: No module named 'azure.mgmt.core'
`;

describe("azSshExtensionRemediation", () => {
  it.each(["mac", "linux"] as const)(
    "recommends the az, pip, and extension install commands on %s",
    (os) => {
      const message = azSshExtensionRemediation(os);
      expect(message).toContain("az extension add --name ssh");
      expect(message).toContain("az upgrade");
      expect(message).toContain("python3 -m ensurepip --upgrade");
    }
  );

  it("omits the pip command on Windows, where python3 is not a real command", () => {
    // The MSI-installed Azure CLI bundles its own Python there; `az upgrade`
    // is the effective fix
    const message = azSshExtensionRemediation("win");
    expect(message).toContain("az extension add --name ssh");
    expect(message).toContain("az upgrade");
    expect(message).not.toContain("python3");
  });
});

describe("classifyAzureCertGenerationError", () => {
  /** A rejected exec() error carrying the Azure CLI's captured output */
  const azError = (stderr: string, stdout = "") =>
    Object.assign(new Error("exited with code 1"), { stdout, stderr });

  const FALLBACK =
    "Failed to generate Azure AD SSH certificate: Error: exited with code 1";

  describe("missing `ssh` extension", () => {
    it.each([
      ["non-interactive auto-install pip failure", AUTO_INSTALL_PIP_FAILURE],
      ["interactive install pip failure", INTERACTIVE_INSTALL_PIP_FAILURE],
    ])("classifies a failed dynamic install: %s", (_name, output) => {
      const message = classifyAzureCertGenerationError(azError(output));
      expect(message).toContain("'ssh' extension");
      expect(message).toContain("az extension add --name ssh");
      // Remediation for the failed install itself
      expect(message).toContain("az upgrade");
      expect(message).toContain("python3 -m ensurepip --upgrade");
    });

    it.each([
      ["dynamic install disabled", DYNAMIC_INSTALL_DISABLED],
      ["command group missing", COMMAND_GROUP_MISSING],
    ])(
      "classifies an unresolved `az ssh` command group: %s",
      (_name, output) => {
        const message = classifyAzureCertGenerationError(azError(output));
        expect(message).toContain("az extension add --name ssh");
      }
    );

    it("classifies output regardless of which stream captured it", () => {
      const message = classifyAzureCertGenerationError(
        azError("", AUTO_INSTALL_PIP_FAILURE)
      );
      expect(message).toContain("az extension add --name ssh");
    });
  });

  describe("broken `ssh` extension", () => {
    it("classifies an extension that is installed but fails to import", () => {
      const message = classifyAzureCertGenerationError(
        azError(EXTENSION_IMPORT_FAILURE)
      );
      expect(message).toContain("az extension remove --name ssh");
      expect(message).toContain("az extension add --name ssh");
    });
  });

  describe("fallback", () => {
    it("does not classify a failure that happened after the extension installed successfully", () => {
      expect(
        classifyAzureCertGenerationError(
          azError(INSTALL_SUCCEEDED_THEN_LOGIN_FAILURE)
        )
      ).toBe(FALLBACK);
    });

    it("returns the generic message for an unrelated error", () => {
      expect(classifyAzureCertGenerationError(azError(LOGIN_FAILURE))).toBe(
        FALLBACK
      );
    });

    it("does not blame the extension for an import failure in the Azure CLI core", () => {
      expect(
        classifyAzureCertGenerationError(azError(CORE_IMPORT_FAILURE))
      ).toBe(FALLBACK);
    });

    it("returns the generic message for empty output", () => {
      expect(classifyAzureCertGenerationError(azError(""))).toBe(FALLBACK);
    });
  });
});
