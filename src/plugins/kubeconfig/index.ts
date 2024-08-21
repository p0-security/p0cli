/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { KubeconfigCommandArgs } from "../../commands/kubeconfig";
import { waitForProvisioning } from "../../commands/shared";
import { request } from "../../commands/shared/request";
import { doc } from "../../drivers/firestore";
import { print2 } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import { Request } from "../../types/request";
import { assertNever } from "../../util";
import { getAwsConfig } from "../aws/config";
import { assumeRoleWithIdc } from "../aws/idc";
import { AwsCredentials } from "../aws/types";
import { assumeRoleWithOktaSaml } from "../okta/aws";
import {
  EksClusterConfig,
  K8sConfig,
  K8sGenerated,
  K8sPermissionSpec,
} from "./types";
import { getDoc } from "firebase/firestore";
import { pick } from "lodash";
import yargs from "yargs";

export const getAndValidateK8sIntegration = async (
  authn: Authn,
  clusterId: string
): Promise<{
  clusterConfig: EksClusterConfig;
  awsLoginType: "federated" | "idc";
}> => {
  const configDoc = await getDoc<K8sConfig, object>(
    doc(`o/${authn.identity.org.tenantId}/integrations/k8s`)
  );

  // Validation done here in lieu of the backend, since the backend doesn't validate until approval. TODO: ENG-2365.
  const clusterConfig = configDoc
    .data()
    ?.workflows.items.find(
      (c) => c.clusterId === clusterId && c.state === "installed"
    );

  if (!clusterConfig) {
    throw `Cluster with ID ${clusterId} not found`;
  }

  const { awsAccountId, awsClusterArn } = clusterConfig;

  if (!awsAccountId || !awsClusterArn) {
    throw (
      `This command currently only supports AWS EKS clusters, and ${clusterId} is not configured as one.\n` +
      "You can request access to the cluster using the `p0 request k8s` command."
    );
  }

  const { config: awsConfig } = await getAwsConfig(authn, awsAccountId);
  const { login: awsLogin } = awsConfig;

  // Verify that the AWS auth type is supported before issuing the requests
  if (!awsLogin?.type || awsLogin?.type === "iam") {
    throw "This AWS account is not configured for kubectl access via the P0 CLI.\nYou can request access to the cluster using the `p0 request k8s` command.";
  }

  return {
    clusterConfig: {
      ...clusterConfig,
      awsAccountId,
      awsClusterArn,
    },
    awsLoginType: awsLogin.type,
  };
};

export const requestAccessToCluster = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<KubeconfigCommandArgs>,
  clusterId: string,
  role: string
): Promise<Request<K8sPermissionSpec>> => {
  const response = await request("request")(
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
  const { id, isPreexisting } = response;
  if (!isPreexisting) {
    print2(
      "Waiting for access to be provisioned. This may take up to a minute."
    );
  }

  return await waitForProvisioning<K8sPermissionSpec>(authn, id);
};

export const profileName = (eksCluterName: string): string =>
  `p0cli-managed-eks-${eksCluterName}`;

export const awsCloudAuth = async (
  authn: Authn,
  awsAccountId: string,
  generated: K8sGenerated,
  loginType: "federated" | "idc"
): Promise<AwsCredentials> => {
  const { eksGenerated } = generated;
  const { name, idc } = eksGenerated;

  switch (loginType) {
    case "idc":
      if (!idc) {
        throw "AWS is configured to use Identity Center, but IDC information wasn't received in the request.";
      }

      return await assumeRoleWithIdc({
        accountId: awsAccountId,
        permissionSet: name,
        idc,
      });
    case "federated":
      return await assumeRoleWithOktaSaml(authn, {
        accountId: awsAccountId,
        role: name,
      });
    default:
      throw assertNever(loginType);
  }
};
