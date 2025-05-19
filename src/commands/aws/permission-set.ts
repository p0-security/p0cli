/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fsShutdownGuard } from "../../drivers/firestore";
import { getAwsConfig } from "../../plugins/aws/config";
import { assumeRoleWithIdc } from "../../plugins/aws/idc";
import { Authn } from "../../types/identity";
import { provisionRequest } from "../shared/request";
import { AssumeCommandArgs, AssumePermissionSetCommandArgs } from "./types";
import { printAwsCredentials } from "./util";
import { pick } from "lodash";
import yargs from "yargs";

export const permissionSet = (
  yargs: yargs.Argv<AssumeCommandArgs>,
  authn: Authn
) =>
  yargs.command(
    "permission-set",
    "Interact with AWS permission sets",
    (yargs) =>
      yargs.command(
        "assume <permission-set>",
        "Assume an AWS permission set",
        (y: yargs.Argv<AssumeCommandArgs>) =>
          y.positional("permission-set", {
            type: "string",
            demandOption: true,
            describe: "An AWS permission set name",
          }),
        fsShutdownGuard((argv) => oktaAwsAssumePermissionSet(argv, authn))
      )
  );

const oktaAwsAssumePermissionSet = async (
  argv: yargs.ArgumentsCamelCase<AssumePermissionSetCommandArgs>,
  authn: Authn
) => {
  const { account, permissionSet } = argv;
  const { config } = await getAwsConfig(authn, account);

  if (config.login?.type !== "idc") {
    throw new Error(
      `Unexpected login type. Expected IDC to be enabled for account ${account}`
    );
  }

  const { login } = config;

  const requestCommand = buildPermissionSetRequestCommand(argv);

  await provisionRequest(requestCommand, authn);

  const awsCredential = await assumeRoleWithIdc({
    accountId: config.id,
    permissionSet,
    idc: { id: login.identityStoreId, region: login.idcRegion },
  });

  const command = `p0 aws${argv.account ? ` --account ${argv.account}` : ""} permission-set assume ${argv.permissionSet}`;
  printAwsCredentials(awsCredential, command);
};

const buildPermissionSetRequestCommand = (
  argv: yargs.ArgumentsCamelCase<AssumePermissionSetCommandArgs>
): yargs.ArgumentsCamelCase<{
  arguments: string[];
  wait?: boolean;
}> => {
  return {
    ...pick(argv, "$0", "_"),
    arguments: [
      "aws",
      "permission-set",
      argv.permissionSet,
      ...(argv.reason ? ["--reason", argv.reason] : []),
      ...(argv.account ? ["--account", argv.account] : []),
    ],
    wait: true,
  };
};
