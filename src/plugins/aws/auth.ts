/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Authn } from "../../types/identity";
import { assumeRoleWithOktaSaml } from "../okta/aws";
import { assumeRoleWithIdc } from "./idc";
import { AwsCredentials, AwsResourcePermissionSpec } from "./types";

export const awsCloudAuth = async (
  authn: Authn,
  aws: AwsResourcePermissionSpec,
  debug?: boolean
): Promise<AwsCredentials> => {
  const { idcId, idcRegion } = aws.permission ?? {};

  if (idcId && idcRegion) {
    return await assumeRoleWithIdc({
      accountId: aws.permission.accountId,
      permissionSet: aws.generated.name,
      idc: { id: idcId, region: idcRegion },
    });
  } else {
    return await assumeRoleWithOktaSaml(
      authn,
      { accountId: aws.permission.accountId, role: aws.generated.name },
      debug
    );
  }
};
