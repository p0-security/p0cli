/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { assumeRoleWithOktaSaml } from "../../plugins/okta/aws";
import { Authn } from "../../types/identity";
import { provisionRequest } from "../shared/request";
import { AssumeRoleCommandArgs } from "./types";
import { printAwsCredentials } from "./util";
import { pick } from "lodash";
import yargs from "yargs";

export const role = (
  yargs: yargs.Argv<{ account: string | undefined }>,
  authn: Authn
) =>
  yargs.command("role", "Interact with AWS roles", (yargs) =>
    yargs
      // this parent command hangs because it doesn't have a handler,
      // while building we'll require an argument which ensures that we'll
      // always correctly display a help message
      .demandCommand(1)
      .command(
        "assume <role>",
        "Assume an AWS role",
        (y: yargs.Argv<{ account: string | undefined }>) =>
          y.positional("role", {
            type: "string",
            demandOption: true,
            describe: "An AWS role name",
          }),
        // TODO: select based on uidLocation
        (argv) => oktaAwsAssumeRole(argv, authn)
      )
  );

/** Assumes a role in AWS via Okta SAML federation.
 *
 * Prerequisites:
 * - AWS is configured with a SAML identity provider
 * - This identity provider is integrated with a
 *   "AWS SAML Account Federation" app in Okta
 * - The AWS SAML identity provider name, Okta domain,
 *   and Okta SAML app identifier are all contained in
 *   the user's identity blob
 * - The requested role is assigned to the user in Okta
 */
const oktaAwsAssumeRole = async (
  argv: yargs.ArgumentsCamelCase<AssumeRoleCommandArgs>,
  authn: Authn
) => {
  const requestCommand = buildRoleRequestCommand(argv);

  await provisionRequest(requestCommand, authn);

  const awsCredential = await assumeRoleWithOktaSaml(authn, {
    accountId: argv.account,
    role: argv.role,
  });

  const command = `p0 aws${argv.account ? ` --account ${argv.account}` : ""} role assume ${argv.role}`;
  printAwsCredentials(awsCredential, command);
};

const buildRoleRequestCommand = (
  argv: yargs.ArgumentsCamelCase<AssumeRoleCommandArgs>
): yargs.ArgumentsCamelCase<{
  arguments: string[];
  wait?: boolean;
}> => {
  return {
    ...pick(argv, "$0", "_"),
    arguments: [
      "aws",
      "role",
      argv.role,
      ...(argv.reason ? ["--reason", argv.reason] : []),
      ...(argv.account ? ["--account", argv.account] : []),
    ],
    wait: true,
  };
};
