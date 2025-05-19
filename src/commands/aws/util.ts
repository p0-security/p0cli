/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print1, print2 } from "../../drivers/stdio";
import { AwsCredentials } from "../../plugins/aws/types";
import { sys } from "typescript";

const CREDENTIAL_FIELDS: (keyof AwsCredentials)[] = [
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_SECURITY_TOKEN",
];

export const printAwsCredentials = (
  awsCredentials: AwsCredentials,
  command: string
) => {
  const isTty = sys.writeOutputIsTTY?.();
  const indent = isTty ? "  " : "";

  if (isTty) print2("Execute the following commands:\n");

  for (const key of CREDENTIAL_FIELDS) {
    const value = awsCredentials[key];
    if (value) {
      print1(`${indent}export ${key}=${value}`);
    }
  }

  if (isTty) {
    print2(`
Or, populate these environment variables using BASH command substitution:
  
  $(${command}) `);
  }
};
