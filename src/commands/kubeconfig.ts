/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { retryWithSleep } from "../common/retry";
import { AnsiSgr } from "../drivers/ansi";
import { authenticate } from "../drivers/auth";
import { guard } from "../drivers/firestore";
import { print2 } from "../drivers/stdio";
import {
  awsCloudAuth,
  profileName,
  requestAccessToCluster,
  getAndValidateK8sIntegration,
} from "../plugins/kubeconfig";
import { ensureEksInstall } from "../plugins/kubeconfig/install";
import { ciEquals, exec } from "../util";
import { writeAwsConfigProfile, writeAwsTempCredentials } from "./aws/files";
import yargs from "yargs";

export type KubeconfigCommandArgs = {
  cluster: string;
  role: string;
  resource?: string;
  reason?: string;
  requestedDuration?: string;
};

export const kubeconfigCommand = (yargs: yargs.Argv) =>
  yargs.command<KubeconfigCommandArgs>(
    "kubeconfig",
    "Request access to and automatically configure kubectl for a k8s cluster hosted by a cloud provider. Currently supports AWS EKS only.",
    (yargs) =>
      yargs
        .option("cluster", {
          type: "string",
          demandOption: true,
          describe: "The ID of the k8s cluster as configured P0 Security",
        })
        .option("resource", {
          type: "string",
          describe:
            'The resource or resource type (e.g., "Pod / *"), or omit for all',
        })
        .option("role", {
          type: "string",
          demandOption: true,
          describe:
            'The k8s role to request, e.g., "ClusterRole / cluster-admin"',
        })
        .option("reason", {
          type: "string",
          describe: "Reason access is needed",
        })
        .option("requested-duration", {
          type: "string",
          // Copied from the P0 backend
          describe:
            "Requested duration for access (format like '10 minutes', '2 hours', '5 days', or '1 week')",
        }),
    guard(kubeconfigAction)
  );

const kubeconfigAction = async (
  args: yargs.ArgumentsCamelCase<KubeconfigCommandArgs>
) => {
  const role = normalizeRoleArg(args.role);

  if (args.resource) {
    validateResourceArg(args.resource);
  }

  const authn = await authenticate();

  const { clusterConfig, awsLoginType } = await getAndValidateK8sIntegration(
    authn,
    args.cluster
  );
  const { clusterId, awsAccountId, awsClusterArn } = clusterConfig;

  if (!(await ensureEksInstall())) {
    throw "Required dependencies are missing; please try again after installing them, or check that they are available on the PATH.";
  }

  const request = await requestAccessToCluster(authn, args, clusterId, role);

  const awsAuth = await awsCloudAuth(
    authn,
    awsAccountId,
    request.generated,
    awsLoginType
  );

  const profile = profileName(clusterId);

  // The `aws eks update-kubeconfig` command can't handle the ARN of the EKS cluster.
  // So we must, with great annoyance, parse it to extract the cluster name and region.
  const clusterInfo = extractClusterNameAndRegion(awsClusterArn);
  const { clusterRegion, clusterName } = clusterInfo;

  await writeAwsTempCredentials(profile, awsAuth);
  await writeAwsConfigProfile(profile, { region: clusterRegion });

  const updateKubeconfigArgs = [
    "eks",
    "update-kubeconfig",
    "--name",
    clusterName,
    "--region",
    clusterRegion,
    "--profile",
    profile,
  ];

  try {
    // Federated access especially sometimes takes some time to propagate, so
    // retry for up to 20 seconds just in case it takes a while.
    const awsResult = await retryWithSleep(
      async () => await exec("aws", updateKubeconfigArgs, { check: true }),
      () => true,
      8,
      2500
    );
    print2(awsResult.stdout);
  } catch (error: any) {
    print2("Failed to invoke `aws eks update-kubeconfig`");
    throw error;
  }

  // `aws update-kubeconfig` will set the kubectl context if it made a change to the kubeconfig file.
  // We'll set the context manually anyway, just in case. `aws update-kubeconfig` names the context
  // with the EKS cluster's ARN.
  try {
    const kubectlResult = await exec(
      "kubectl",
      ["config", "use-context", awsClusterArn],
      { check: true }
    );
    print2(kubectlResult.stdout);
  } catch (error: any) {
    print2("Failed to invoke `kubectl config use-context`");
    throw error;
  }

  print2(
    "Access granted and kubectl configured successfully. Re-run this command to refresh access if credentials expire."
  );

  if (process.env.AWS_ACCESS_KEY_ID) {
    print2(
      `${AnsiSgr.Yellow}Warning: AWS credentials were detected in your environment, which may cause kubectl errors. ` +
        `To avoid issues, unset with \`unset AWS_ACCESS_KEY_ID\`.${AnsiSgr.Reset}`
    );
  }
};

/**
 * Normalize the role argument to the format expected by the P0 backend,
 * matching the way the Slack modal formats the role. Also validates that the
 * role argument contains the components expected by the backend without having
 * to make the request first.
 *
 * Currently, the P0 backend does not validate request arguments until after a
 * request is approved; this function allows the validation to be done up-front
 * pending a future backend change. TODO: ENG-2365.
 *
 * @param role The role argument to normalize
 * @returns The normalized role value to pass to the backend
 */
const normalizeRoleArg = (role: string): string => {
  const SEPARATOR = "/";
  const SYNTAX_HINT =
    "The role argument must be in one of the following formats:\n" +
    "- ClusterRole/<roleName>\n" +
    "- CuratedRole/<roleName>\n" +
    "- Role/<namespace>/<roleName>";

  const items = role.split(SEPARATOR).map((item) => item.trim());

  if (items.length < 2 || items.length > 3) {
    throw `Invalid format for role argument.\n${SYNTAX_HINT}`;
  }

  if (!items[0]) {
    throw `Role kind must be specified.\n${SYNTAX_HINT}`;
  }

  if (ciEquals(items[0], "ClusterRole")) {
    return `ClusterRole ${SEPARATOR} ${items[1]}`;
  } else if (ciEquals(items[0], "CuratedRole")) {
    return `CuratedRole ${SEPARATOR} ${items[1]}`;
  } else if (ciEquals(items[0], "Role")) {
    if (items.length !== 3) {
      throw `Invalid format for role argument.\n${SYNTAX_HINT}`;
    }
    return `Role ${SEPARATOR} ${items[1]} ${SEPARATOR} ${items[2]}`;
  }

  throw `Invalid role kind ${items[0]}.\n${SYNTAX_HINT}`;
};

/**
 * Validate that the resource argument is of the format expected by the P0
 * backend, again matching the way the Slack modal formats the resource.
 *
 * Currently, the P0 backend does not validate request arguments until after a
 * request is approved; this function allows the validation to be done up-front
 * pending a future backend change. TODO: ENG-2365.
 *
 * @param resource The resource argument to validate
 */
const validateResourceArg = (resource: string): void => {
  const SEPARATOR = " / ";

  const items = resource.split(SEPARATOR);

  if (items.length < 2 || items.length > 3) {
    throw (
      "Invalid format for resource argument.\n" +
      "The resource argument must be in one of the following formats (spaces required):\n" +
      "- <kind> / <namespace> / <name>\n" +
      "- <kind> / <name>"
    );
  }
};

const extractClusterNameAndRegion = (clusterArn: string) => {
  const INVALID_ARN_MSG = `Invalid EKS cluster ARN: ${clusterArn}`;
  // Example EKS cluster ARN: arn:aws:eks:us-west-2:123456789012:cluster/my-testing-cluster
  const parts = clusterArn.split(":");

  if (parts.length < 6 || !parts[3] || !parts[5]) {
    throw INVALID_ARN_MSG;
  }

  const clusterRegion = parts[3];
  const resource = parts[5].split("/");

  if (resource[0] !== "cluster") {
    throw INVALID_ARN_MSG;
  }

  const clusterName = resource[1];

  if (!clusterName) {
    throw INVALID_ARN_MSG;
  }

  return { clusterRegion, clusterName };
};
