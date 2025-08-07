/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { KubeconfigCommandArgs } from "../../commands/kubeconfig";
import { decodeProvisionStatus } from "../../commands/shared";
import { request } from "../../commands/shared/request";
import { fetchIntegrationConfig } from "../../drivers/api";
import { Authn } from "../../types/identity";
import { PermissionRequest } from "../../types/request";
import { assertNever } from "../../util";
import { getAwsConfig } from "../aws/config";
import { assumeRoleWithIdc } from "../aws/idc";
import { AwsCredentials } from "../aws/types";
import { parseArn } from "../aws/utils";
import { assumeRoleWithOktaSaml } from "../okta/aws";
import { K8sConfig, K8sPermissionSpec } from "./types";
import { pick } from "lodash";
import { sys } from "typescript";
import yargs from "yargs";

const KUBECONFIG_PREFIX = "p0";

export const getAndValidateK8sIntegration = async (
  authn: Authn,
  clusterId: string
): Promise<{
  clusterConfig: {
    clusterId: string;
    awsAccountId: string;
    awsClusterArn: string;
  };
  awsLoginType: "federated" | "idc";
}> => {
  const configDoc = await fetchIntegrationConfig<{ config: K8sConfig }>(
    authn,
    "k8s"
  );

  // Validation done here in lieu of the backend, since the backend doesn't validate until approval. TODO: ENG-2365.
  const config = configDoc.config["iam-write"]?.[clusterId];
  if (!config) {
    throw `Cluster with ID ${clusterId} not found`;
  }

  if (config.state !== "installed") {
    throw `Cluster with ID ${clusterId} is not installed`;
  }

  const { hosting } = config;

  if (hosting.type !== "aws") {
    throw (
      `This command currently only supports AWS EKS clusters, and ${clusterId} is not configured as one.\n` +
      "You can request access to the cluster using the `p0 request k8s` command."
    );
  }

  const { arn: awsClusterArn } = hosting;
  const { accountId: awsAccountId } = parseArn(awsClusterArn);
  const { config: awsConfig } = await getAwsConfig(authn, awsAccountId);
  const { login: awsLogin } = awsConfig;

  // Verify that the AWS auth type is supported before issuing the requests
  if (!awsLogin?.type || awsLogin?.type === "iam") {
    throw "This AWS account is not configured for kubectl access via the P0 CLI.\nYou can request access to the cluster using the `p0 request k8s` command.";
  }

  return {
    clusterConfig: { clusterId, awsAccountId, awsClusterArn },
    awsLoginType: awsLogin.type,
  };
};

export const requestAccessToCluster = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<KubeconfigCommandArgs>,
  clusterId: string,
  role: string
): Promise<PermissionRequest<K8sPermissionSpec>> => {
  const response = await request("request")<
    PermissionRequest<K8sPermissionSpec>
  >(
    {
      ...pick(args, "$0", "_"),
      arguments: [
        "k8s",
        "resource",
        "--cluster",
        clusterId,
        "--role",
        role,
        ...(args.resource ? ["--locator", args.resource] : []),
        ...(args.reason ? ["--reason", args.reason] : []),
        ...(args.requestedDuration
          ? ["--requested-duration", args.requestedDuration]
          : []),
      ],
      wait: true,
    },
    authn,
    { message: "approval-required" }
  );

  if (!response) {
    throw "Did not receive access ID from server";
  }

  const code = await decodeProvisionStatus(response.request);
  if (!code) {
    sys.exit(1);
  }
  return response.request;
};

export const profileName = (eksCluterName: string): string =>
  `${KUBECONFIG_PREFIX}-${eksCluterName}`;

export const aliasedArn = (eksCluterArn: string): string =>
  `${KUBECONFIG_PREFIX}-${eksCluterArn}`;

export const awsCloudAuth = async (
  authn: Authn,
  awsAccountId: string,
  request: PermissionRequest<K8sPermissionSpec>,
  loginType: "federated" | "idc"
): Promise<AwsCredentials> => {
  const { permission, generated } = request;
  const { eksGenerated } = generated;
  const { name } = eksGenerated;

  switch (loginType) {
    case "idc": {
      const { idcId, idcRegion } = permission.awsResourcePermission ?? {};

      if (!idcId || !idcRegion) {
        throw "AWS is configured to use Identity Center, but IDC information wasn't received in the request.";
      }

      return await assumeRoleWithIdc({
        accountId: awsAccountId,
        permissionSet: name,
        idc: { id: idcId, region: idcRegion },
      });
    }
    case "federated":
      return await assumeRoleWithOktaSaml(authn, {
        accountId: awsAccountId,
        role: name,
      });
    default:
      throw assertNever(loginType);
  }
};
