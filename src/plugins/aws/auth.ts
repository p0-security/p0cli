/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { getDelegate } from "../../types/delegation";
import { Authn } from "../../types/identity";
import { assumeRoleWithOktaSaml } from "../okta/aws";
import { assumeRoleWithIdc } from "./idc";
import { AwsCredentials, AwsResourcePermissionSpec } from "./types";

/** Gets the role, as `path/Name`, of a grant through an AWS IAM Federation pool */
const federationPoolRole = (aws: AwsResourcePermissionSpec) => {
  const federation = getDelegate(aws.delegation, "aws-iam-federation");
  const provider = getDelegate(
    federation?.delegation,
    "okta-aws-iam-federation"
  );
  const pool = getDelegate(provider?.delegation, "aws-iam-federation");
  return pool?.generated.arn.split("/").slice(1).join("/");
};

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
      {
        accountId: aws.permission.accountId,
        role: federationPoolRole(aws) ?? aws.generated.name,
      },
      debug
    );
  }
};
