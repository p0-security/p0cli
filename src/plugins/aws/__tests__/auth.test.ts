/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Authn } from "../../../types/identity";
import { assumeRoleWithOktaSaml } from "../../okta/aws";
import { awsCloudAuth } from "../auth";
import { AwsResourcePermissionSpec } from "../types";
import { describe, expect, it, vi } from "vitest";

vi.mock("../../okta/aws");

const authn = {} as Authn;

const aws: AwsResourcePermissionSpec = {
  type: "aws",
  permission: {
    account: "123456789012",
    accountId: "123456789012",
    arn: "arn:aws:rds-db:us-west-2:123456789012:dbuser:db-ABC/p0_user",
    idcId: undefined,
    idcRegion: undefined,
    name: "",
  },
  generated: { name: "P0GrantsRole" },
};

describe("awsCloudAuth", () => {
  it("assumes the generated role", async () => {
    await awsCloudAuth(authn, aws);
    expect(assumeRoleWithOktaSaml).toHaveBeenCalledWith(
      authn,
      { accountId: "123456789012", role: "P0GrantsRole" },
      undefined
    );
  });

  it("assumes the pool role of an AWS IAM Federation grant", async () => {
    await awsCloudAuth(authn, {
      ...aws,
      generated: { name: "_unused" },
      delegation: [
        {
          key: "aws-iam-federation",
          request: {
            type: "aws-iam-federation",
            permission: {},
            generated: undefined,
            delegation: [
              {
                key: "okta-aws-iam-federation",
                request: {
                  type: "okta-aws-iam-federation",
                  permission: {},
                  generated: undefined,
                  delegation: [
                    {
                      key: "aws-iam-federation",
                      request: {
                        type: "aws-iam-federation",
                        permission: {},
                        generated: {
                          arn: "arn:aws:iam::123456789012:role/p0/federation/P0Pool-1",
                        },
                      },
                    },
                  ],
                },
              },
            ],
          },
        },
      ],
    });
    expect(assumeRoleWithOktaSaml).toHaveBeenCalledWith(
      authn,
      { accountId: "123456789012", role: "p0/federation/P0Pool-1" },
      undefined
    );
  });
});
