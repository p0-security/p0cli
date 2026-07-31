/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { getOperatingSystem } from "../../util";

/**
 * Azure SSH access requires the Azure CLI's `ssh` extension (for `az ssh
 * cert`). `ensureAzInstall` checks for the extension and offers to install it
 * before the connection is attempted, so this classifier is a backstop for the
 * cases that slip through: the user declined the guided install, or the
 * extension broke between the check and `az ssh cert` running.
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

export const AZ_SSH_EXTENSION_ADD_COMMAND = "az extension add --name ssh";

/** Advice for the known failure mode of `az extension add --name ssh`: the
 * install dying at the pip step. Shown by the guided install in install.ts
 * (as the extension item's failureHint) and by the classifier below, so both
 * paths give the user the same commands.
 *
 * On Windows the Azure CLI (MSI install) bundles its own Python, and
 * `python3` is usually not a real command there, so recommending ensurepip
 * would be a dead end; reinstalling/updating the Azure CLI is the effective
 * fix on that platform. */
export const azSshExtensionPipHint = (
  os: ReturnType<typeof getOperatingSystem> = getOperatingSystem()
) =>
  os === "win"
    ? `If that command fails with a pip error, update the Azure CLI:\n\n` +
      `  az upgrade\n`
    : `If that command fails with a pip error, update the Azure CLI and pip:\n\n` +
      `  az upgrade\n` +
      `  python3 -m ensurepip --upgrade\n`;

/** Remediation commands when the `ssh` extension can not be installed
 * automatically. */
export const azSshExtensionRemediation = (
  os: ReturnType<typeof getOperatingSystem> = getOperatingSystem()
) =>
  `To install the extension manually, run:\n\n` +
  `  ${AZ_SSH_EXTENSION_ADD_COMMAND}\n\n` +
  azSshExtensionPipHint(os) +
  `\nThen run '${AZ_SSH_EXTENSION_ADD_COMMAND}' again, and retry this p0 command.`;

// Leads with a newline so it prints with one blank line above the preceding
// Azure CLI output, for legibility.
const missingSshExtensionMessage = () =>
  `\nFailed to generate an Azure AD SSH certificate: the Azure CLI's 'ssh' ` +
  `extension is not installed, and it could not be installed automatically.` +
  `\n\n${azSshExtensionRemediation()}`;

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
    ? missingSshExtensionMessage()
    : undefined;
};
