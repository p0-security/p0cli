/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

/**
 * Azure SSH access requires the Azure CLI's `ssh` extension (for `az ssh
 * cert`). The extension is not part of the base Azure CLI install; when it is
 * missing, the CLI normally installs it on first use, but that dynamic install
 * can fail — most commonly at the pip step, in environments where the CLI
 * cannot write to its own extension directory — or be disabled outright.
 *
 * Historically the user saw only the raw Azure CLI output followed by a
 * generic "Failed to generate Azure AD SSH certificate" error, and concluded
 * P0 was broken. We surface a targeted hint instead.
 *
 * The Azure CLI's "The command requires the extension ssh" warning alone is
 * benign — when the dynamic install succeeds, the command continues and exits
 * zero. So on its own it must NOT trigger the hint (the terminal failure could
 * be unrelated, e.g. an expired login, and misattributing it to the extension
 * is worse than the status quo). The hint triggers only when the output also
 * shows the install itself failing, or when the `ssh` command group does not
 * resolve at all (dynamic install disabled or unsupported).
 */

/** The dynamic install of the `ssh` extension was attempted. */
const EXTENSION_INSTALL_ATTEMPTED_PATTERN =
  /The command requires the extension ssh/;

/** The dynamic install failed at the pip step. */
const PIP_INSTALL_FAILED_PATTERN = /Pip failed with status code/;

/** The `ssh` command group does not resolve: the extension is not installed
 * and the Azure CLI did not attempt a dynamic install. The wording varies by
 * Azure CLI version and configuration. */
const SSH_COMMAND_GROUP_MISSING_PATTERNS = [
  /'ssh' is not in the 'az' command group/,
  /'ssh' is misspelled or not recognized by the system/,
];

// Leads with a newline so it prints with one blank line above the preceding
// Azure CLI output, for legibility.
const MISSING_SSH_EXTENSION_MESSAGE =
  `\nFailed to generate an Azure AD SSH certificate because the Azure CLI's ` +
  `'ssh' extension is not installed, and it could not be installed ` +
  `automatically. Install it manually by running 'az extension add --name ` +
  `ssh', then retry this command. If that install fails, update the Azure ` +
  `CLI to the latest version and retry it.`;

/**
 * Inspects the captured output of a failed `az ssh cert` invocation and
 * returns an actionable message when the failure is a missing `ssh` extension
 * (including a failed on-the-fly install of it), or `undefined` to fall
 * through to the raw error.
 */
export const classifyAzureCertGenerationError = (
  output: string
): string | undefined => {
  const installFailed =
    EXTENSION_INSTALL_ATTEMPTED_PATTERN.test(output) &&
    PIP_INSTALL_FAILED_PATTERN.test(output);
  const extensionUnavailable = SSH_COMMAND_GROUP_MISSING_PATTERNS.some(
    (pattern) => pattern.test(output)
  );
  return installFailed || extensionUnavailable
    ? MISSING_SSH_EXTENSION_MESSAGE
    : undefined;
};
