/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { getOperatingSystem } from "../../util";

const EXTENSION_INSTALL_ATTEMPTED_PATTERN =
  /The command requires the extension ssh/;

const PIP_INSTALL_FAILED_PATTERN = /Pip failed with status code/;

const SSH_COMMAND_GROUP_MISSING_PATTERNS = [
  /'ssh' is not in the 'az' command group/,
  /'ssh' is misspelled or not recognized by the system/,
];

export const AZ_SSH_EXTENSION_ADD_COMMAND = "az extension add --name ssh";

export const azSshExtensionPipHint = (
  os: ReturnType<typeof getOperatingSystem> = getOperatingSystem()
) =>
  os === "win"
    ? `If that command fails with a pip error, update the Azure CLI:\n\n` +
      `  az upgrade\n`
    : `If that command fails with a pip error, update the Azure CLI and pip:\n\n` +
      `  az upgrade\n` +
      `  python3 -m ensurepip --upgrade\n`;

export const azSshExtensionRemediation = (
  os: ReturnType<typeof getOperatingSystem> = getOperatingSystem()
) =>
  `To install the extension manually, run:\n\n` +
  `  ${AZ_SSH_EXTENSION_ADD_COMMAND}\n\n` +
  azSshExtensionPipHint(os) +
  `\nThen run '${AZ_SSH_EXTENSION_ADD_COMMAND}' again, and retry this p0 command.`;

const missingSshExtensionMessage = () =>
  `\nFailed to generate an Azure AD SSH certificate: the Azure CLI's 'ssh' ` +
  `extension is not installed, and it could not be installed automatically.` +
  `\n\n${azSshExtensionRemediation()}`;

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
