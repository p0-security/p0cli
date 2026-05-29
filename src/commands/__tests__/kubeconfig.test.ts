/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { spinUntil } from "../../drivers/stdio";
import { awsCloudAuth } from "../../plugins/aws/auth";
import { AwsResourcePermissionSpec } from "../../plugins/aws/types";
import {
  getAndValidateK8sIntegration,
  requestAccessToCluster,
} from "../../plugins/kubeconfig";
import { ensureEksInstall } from "../../plugins/kubeconfig/install";
import { K8sPermissionSpec } from "../../plugins/kubeconfig/types";
import { PermissionRequest } from "../../types/request";
import { exec } from "../../util";
import { writeAwsConfigProfile, writeAwsTempCredentials } from "../aws/files";
import { kubeconfigCommand } from "../kubeconfig";
import { noop } from "lodash";
import { afterEach, beforeEach, describe, expect, it, vi, Mock } from "vitest";
import yargs from "yargs";

vi.mock("../../drivers/auth", () => ({
  authenticate: vi.fn(async () => ({ identity: { email: "u@p0.app" } })),
}));
vi.mock("../../drivers/stdio", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../drivers/stdio")>()),
  print2: vi.fn(),
  spinUntil: vi.fn(async (_msg, action) => action),
}));
vi.mock("../../plugins/aws/auth");
vi.mock("../../plugins/kubeconfig");
vi.mock("../../plugins/kubeconfig/install");
vi.mock("../aws/files");
vi.mock("../../util", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../util")>()),
  exec: vi.fn(async () => ({ stdout: "ok", stderr: "", code: 0 })),
}));

const mockAwsCloudAuth = awsCloudAuth as Mock;
const mockGetAndValidateK8sIntegration = getAndValidateK8sIntegration as Mock;
const mockEnsureEksInstall = ensureEksInstall as Mock;
const mockRequestAccessToCluster = requestAccessToCluster as Mock;
const mockWriteAwsTempCredentials = writeAwsTempCredentials as Mock;
const mockWriteAwsConfigProfile = writeAwsConfigProfile as Mock;
const mockSpinUntil = spinUntil as unknown as Mock;
const mockExec = exec as Mock;

const AWS_DELEGATE: AwsResourcePermissionSpec = {
  type: "aws",
  permission: {
    account: "acct",
    accountId: "111111111111",
    arn: "arn:aws:iam::111111111111:role/foo",
    idcId: undefined,
    idcRegion: undefined,
    name: "p0-role",
  },
  generated: { name: "p0-role" },
  delegation: {},
};

const buildRequest = (
  delegation: K8sPermissionSpec["delegation"]
): PermissionRequest<K8sPermissionSpec> => ({
  type: "k8s",
  permission: {
    resource: { name: "*", namespace: "*", kind: "Pod" },
    role: "ClusterRole / view",
    clusterId: "c-1",
    type: "resource",
  },
  generated: { role: "p0-generated-role" },
  delegation,
  status: "DONE",
  principal: "u@p0.app",
});

const runKubeconfig = async () =>
  kubeconfigCommand(yargs())
    .fail(noop)
    .parse(
      "kubeconfig --cluster c-1 --role ClusterRole/view"
    ) as unknown as Promise<unknown>;

describe("kubeconfigAction", () => {
  beforeEach(() => {
    mockGetAndValidateK8sIntegration.mockResolvedValue({
      clusterConfig: {
        clusterId: "c-1",
        awsAccountId: "111111111111",
        awsClusterArn: "arn:aws:eks:us-east-1:111111111111:cluster/my-cluster",
      },
      awsLoginType: "federated",
    });
    mockEnsureEksInstall.mockResolvedValue(true);
    mockAwsCloudAuth.mockResolvedValue({
      AWS_ACCESS_KEY_ID: "k",
      AWS_SECRET_ACCESS_KEY: "s",
      AWS_SESSION_TOKEN: "t",
      AWS_SECURITY_TOKEN: "t",
    });
    mockSpinUntil.mockImplementation(
      async (_msg: string, action: any) => action
    );
    mockExec.mockResolvedValue({ stdout: "ok", stderr: "", code: 0 });
    mockWriteAwsTempCredentials.mockResolvedValue(undefined);
    mockWriteAwsConfigProfile.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("passes the aws delegate to awsCloudAuth when delegation is in legacy record form", async () => {
    mockRequestAccessToCluster.mockResolvedValue(
      buildRequest({ aws: AWS_DELEGATE })
    );

    await runKubeconfig();

    expect(mockAwsCloudAuth).toHaveBeenCalledOnce();
    expect(mockAwsCloudAuth.mock.calls[0]?.[1]).toEqual(AWS_DELEGATE);
  });

  it("passes the aws delegate to awsCloudAuth when delegation is in new array form", async () => {
    mockRequestAccessToCluster.mockResolvedValue(
      buildRequest([{ key: "aws", request: AWS_DELEGATE }])
    );

    await runKubeconfig();

    expect(mockAwsCloudAuth).toHaveBeenCalledOnce();
    expect(mockAwsCloudAuth.mock.calls[0]?.[1]).toEqual(AWS_DELEGATE);
  });

  it("throws when delegation is array-form but has no aws entry", async () => {
    mockRequestAccessToCluster.mockResolvedValue(buildRequest([]));

    await expect(runKubeconfig()).rejects.toBe(
      "Backend granted k8s access, but this is not an EKS cluster."
    );
    expect(mockAwsCloudAuth).not.toHaveBeenCalled();
  });

  it("resolves equivalent shapes identically", async () => {
    mockRequestAccessToCluster.mockResolvedValueOnce(
      buildRequest({ aws: AWS_DELEGATE })
    );
    await runKubeconfig();
    const recordCallArg = mockAwsCloudAuth.mock.calls[0]?.[1];

    vi.clearAllMocks();
    mockGetAndValidateK8sIntegration.mockResolvedValue({
      clusterConfig: {
        clusterId: "c-1",
        awsAccountId: "111111111111",
        awsClusterArn: "arn:aws:eks:us-east-1:111111111111:cluster/my-cluster",
      },
      awsLoginType: "federated",
    });
    mockEnsureEksInstall.mockResolvedValue(true);
    mockAwsCloudAuth.mockResolvedValue({
      AWS_ACCESS_KEY_ID: "k",
      AWS_SECRET_ACCESS_KEY: "s",
      AWS_SESSION_TOKEN: "t",
      AWS_SECURITY_TOKEN: "t",
    });
    mockSpinUntil.mockImplementation(
      async (_msg: string, action: any) => action
    );
    mockExec.mockResolvedValue({ stdout: "ok", stderr: "", code: 0 });
    mockRequestAccessToCluster.mockResolvedValueOnce(
      buildRequest([{ key: "aws", request: AWS_DELEGATE }])
    );
    await runKubeconfig();
    const arrayCallArg = mockAwsCloudAuth.mock.calls[0]?.[1];

    expect(arrayCallArg).toEqual(recordCallArg);
  });
});
