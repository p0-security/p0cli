/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchIntegrationConfig } from "../../../drivers/api";
import { awsCloudAuth } from "../../../plugins/aws/auth";
import { AwsResourcePermissionSpec } from "../../../plugins/aws/types";
import { DbPermissionSpec } from "../../../plugins/db/types";
import { failure } from "../../../testing/yargs";
import { Authn } from "../../../types/identity";
import { PermissionRequest } from "../../../types/request";
import { exec } from "../../../util";
import { decodeProvisionStatus } from "../../shared";
import { request } from "../../shared/request";
import { writeAwsConfigProfile, writeAwsTempCredentials } from "../files";
import { rds } from "../rds";
import { afterEach, beforeEach, describe, expect, it, vi, Mock } from "vitest";
import yargs from "yargs";

vi.mock("../../../drivers/api");
vi.mock("../../../drivers/auth");
vi.mock("../../../drivers/stdio", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../drivers/stdio")>()),
  print1: vi.fn(),
  print2: vi.fn(),
}));
vi.mock("../../../plugins/aws/auth");
vi.mock("../files");
vi.mock("../../shared", () => ({
  decodeProvisionStatus: vi.fn(),
}));
vi.mock("../../shared/request", () => ({
  request: vi.fn(),
}));
vi.mock("../../../util", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../util")>()),
  exec: vi.fn(),
}));

const mockRequest = request as unknown as Mock;
const mockDecodeProvisionStatus = decodeProvisionStatus as Mock;
const mockAwsCloudAuth = awsCloudAuth as Mock;
const mockFetchIntegrationConfig = fetchIntegrationConfig as Mock;
const mockWriteAwsTempCredentials = writeAwsTempCredentials as Mock;
const mockWriteAwsConfigProfile = writeAwsConfigProfile as Mock;
const mockExec = exec as Mock;

const AWS_DELEGATE: AwsResourcePermissionSpec = {
  type: "aws",
  permission: {
    account: "acct",
    accountId: "111111111111",
    arn: "arn:aws:rds:us-east-1:111111111111:db:my-db",
    idcId: undefined,
    idcRegion: undefined,
    name: "p0-rds-role",
  },
  generated: { name: "p0-rds-role" },
  delegation: {},
};

const buildAccess = (
  delegation: DbPermissionSpec["delegation"]
): PermissionRequest<DbPermissionSpec> => ({
  type: "postgres",
  permission: { instanceId: "db-1" },
  generated: {},
  delegation,
  status: "DONE",
  principal: "user@p0.app",
});

const FAKE_AUTHN: Authn = {
  identity: { org: { slug: "test", tenantId: "t" } },
} as unknown as Authn;

const buildRdsYargs = () => rds(yargs() as any, FAKE_AUTHN);

describe("rds generate-db-auth-token", () => {
  beforeEach(() => {
    // request() is curried: request("request")(args, authn, options)
    mockRequest.mockReturnValue(async () => undefined);
    mockDecodeProvisionStatus.mockResolvedValue(1);
    mockAwsCloudAuth.mockResolvedValue({
      AWS_ACCESS_KEY_ID: "k",
      AWS_SECRET_ACCESS_KEY: "s",
      AWS_SESSION_TOKEN: "t",
      AWS_SECURITY_TOKEN: "t",
    });
    mockFetchIntegrationConfig.mockResolvedValue({
      config: {
        "iam-write": {
          "db-1": {
            hostname: "db.host",
            port: "5432",
            hosting: {
              type: "aws-rds",
              databaseArn: "arn:aws:rds:us-east-1:111111111111:db:my-db",
              vpcId: "vpc-1",
            },
            state: "installed",
          },
        },
      },
    });
    mockWriteAwsTempCredentials.mockResolvedValue(undefined);
    mockWriteAwsConfigProfile.mockResolvedValue(undefined);
    mockExec.mockResolvedValue({
      stdout: "fake-rds-token",
      stderr: "",
      code: null,
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  const mockAccessResponse = (
    delegation: DbPermissionSpec["delegation"]
  ): void => {
    mockRequest.mockReturnValue(async () => ({
      ok: true,
      message: "approved",
      id: "req-1",
      isPreexisting: false,
      isPersistent: false,
      isPreapproved: false,
      request: buildAccess(delegation),
    }));
  };

  it("passes the inner aws delegate to awsCloudAuth (legacy nested record form)", async () => {
    mockAccessResponse({
      "aws-rds": {
        permission: { vpcId: "vpc-1" },
        delegation: { aws: AWS_DELEGATE },
      },
    });

    await buildRdsYargs().parse(
      "rds generate-db-auth-token --arch postgres --role admin"
    );

    expect(mockAwsCloudAuth).toHaveBeenCalledOnce();
    expect(mockAwsCloudAuth.mock.calls[0]?.[1]).toEqual(AWS_DELEGATE);
  });

  it("passes the inner aws delegate to awsCloudAuth (new array form at both levels)", async () => {
    mockAccessResponse([
      {
        key: "aws-rds",
        request: {
          permission: { vpcId: "vpc-1" },
          delegation: [{ key: "aws", request: AWS_DELEGATE }],
        },
      },
    ]);

    await buildRdsYargs().parse(
      "rds generate-db-auth-token --arch postgres --role admin"
    );

    expect(mockAwsCloudAuth).toHaveBeenCalledOnce();
    expect(mockAwsCloudAuth.mock.calls[0]?.[1]).toEqual(AWS_DELEGATE);
  });

  it("supports mixed nesting (array outer, record inner)", async () => {
    mockAccessResponse([
      {
        key: "aws-rds",
        request: {
          permission: { vpcId: "vpc-1" },
          delegation: { aws: AWS_DELEGATE },
        },
      },
    ]);

    await buildRdsYargs().parse(
      "rds generate-db-auth-token --arch postgres --role admin"
    );

    expect(mockAwsCloudAuth.mock.calls[0]?.[1]).toEqual(AWS_DELEGATE);
  });

  it("supports mixed nesting (record outer, array inner)", async () => {
    mockAccessResponse({
      "aws-rds": {
        permission: { vpcId: "vpc-1" },
        delegation: [{ key: "aws", request: AWS_DELEGATE }],
      },
    });

    await buildRdsYargs().parse(
      "rds generate-db-auth-token --arch postgres --role admin"
    );

    expect(mockAwsCloudAuth.mock.calls[0]?.[1]).toEqual(AWS_DELEGATE);
  });

  it("throws when array-form delegation is missing the aws-rds entry", async () => {
    mockAccessResponse([]);

    const error = await failure(
      buildRdsYargs(),
      "rds generate-db-auth-token --arch postgres --role admin"
    );

    expect(error).toBe("P0 granted access, but db-1 is not a RDS instance.");
    expect(mockAwsCloudAuth).not.toHaveBeenCalled();
  });
});
