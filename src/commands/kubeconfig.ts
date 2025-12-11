/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { retryWithSleep } from "../common/retry";
import { AnsiSgr } from "../drivers/ansi";
import { authenticate } from "../drivers/auth";
import { print2, spinUntil } from "../drivers/stdio";
import { parseArn } from "../plugins/aws/utils";
import {
  aliasedArn,
  awsCloudAuth,
  getAndValidateK8sIntegration,
  gcpKubeconfig,
  K8sIntegrationConfig,
  profileName,
  requestAccessToCluster,
} from "../plugins/kubeconfig";
import { ciEquals, exec, getAppName } from "../util";
import { writeAwsConfigProfile, writeAwsTempCredentials } from "./aws/files";
import { asyncSpawn } from "../common/subprocess";
import { sys } from "typescript";
import yargs from "yargs";

export type KubeconfigCommandArgs = {
  cluster: string;
  role: string;
  resource?: string;
  reason?: string;
  duration?: string;
  debug?: boolean;
};

// The P0 backend must be updated if this CLI command changes!
// This command is rendered to the user once a k8s request is approved.
export const kubeconfigCommand = (yargs: yargs.Argv) =>
  yargs.command<KubeconfigCommandArgs>(
    "kubeconfig",
    "Request access to and automatically configure kubectl for a k8s cluster hosted by a cloud provider. Supports AWS EKS and GCP GKE.",
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
        .option("duration", {
          type: "string",
          // Copied from the P0 backend
          describe:
            "Requested duration for access (format like '10 minutes', '2 hours', '5 days', or '1 week')",
        })
        .option("debug", {
          type: "boolean",
          describe: "Print debug information.",
        })
        .usage("$0 kubeconfig --cluster <CLUSTER_ID> --role <ROLE_NAME>")
        .epilogue(
          `Request access to and automatically configure kubectl for a Kubernetes cluster.

Supports both AWS EKS and GCP GKE clusters. The command automatically
detects the provider and uses the appropriate authentication method.

For AWS EKS:
  - Uses AWS SSO IAM authentication
  - Automatically configures AWS SSO and generates credentials
  - Configures kubectl with the cluster credentials

For GCP GKE:
  - Uses gcloud authentication
  - Automatically gets cluster credentials via gcloud
  - Configures kubectl with the cluster context

Example:
  $ ${getAppName()} kubeconfig --cluster my-cluster --role "ClusterRole / cluster-admin" --reason "Need to debug production issue"`
        ),
    kubeconfigAction
  );

/**
 * Request access to and automatically configure kubectl for a k8s cluster
 *
 * Implicitly requests access to the cluster if not already granted.
 * Supports both AWS EKS and GCP GKE clusters.
 *
 * For AWS EKS:
 * - Automatically configures AWS SSO and generates credentials
 * - Uses 'aws eks update-kubeconfig' to configure kubectl
 * - Sets the kubectl context to the cluster
 *
 * For GCP GKE:
 * - Uses gcloud authentication
 * - Uses 'gcloud container clusters get-credentials' to configure kubectl
 * - Sets the kubectl context to the cluster
 */
const kubeconfigAction = async (
  args: yargs.ArgumentsCamelCase<KubeconfigCommandArgs>
) => {
  const role = normalizeRoleArg(args.role);

  if (args.resource) {
    validateResourceArg(args.resource);
  }

  // Validate all required tools BEFORE authentication/request
  // Check kubectl, aws CLI, and gcloud CLI (we don't know provider yet, so check both)
  await validateKubeconfigTools(args.debug);

  const authn = await authenticate();

  const integrationConfig = await getAndValidateK8sIntegration(
    authn,
    args.cluster,
    args.debug
  );

  // Tools already validated early, proceed with request
  // No spinUntil(); there is one inside requestAccessToCluster() if needed
  const request = await requestAccessToCluster(
    authn,
    args,
    integrationConfig.clusterId,
    role
  );

  // Route to provider-specific flow
  if (integrationConfig.provider === "gcp") {
    // GCP GKE flow
    // Tools already validated early, proceed with GCP flow
    await gcpKubeconfig(request, integrationConfig.clusterId, integrationConfig, args.debug);

    print2(
      "Access granted and kubectl configured successfully. Re-run this command to refresh access if credentials expire."
    );
    return;
  }

  // AWS EKS flow
  // Tools already validated early, proceed with AWS flow
  const { awsAccountId, awsClusterArn, awsLoginType } = integrationConfig;

  // Tools already validated early, proceed with AWS flow
  const awsAuth = await awsCloudAuth(
    authn,
    awsAccountId,
    request,
    awsLoginType,
    args.debug
  );

  const profile = profileName(integrationConfig.clusterId);
  const alias = aliasedArn(awsClusterArn);

  // The `aws eks update-kubeconfig` command can't handle the ARN of the EKS cluster.
  // So we must, with great annoyance, parse it to extract the cluster name and region.
  const { clusterRegion, clusterName } =
    extractClusterNameAndRegion(awsClusterArn);

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
    // The alias and user-alias are used to avoid conflicts with existing kubeconfig cluster and user in the kubeconfig file.
    // If aliases are not provided, they default to the cluster ARN. See https://awscli.amazonaws.com/v2/documentation/api/latest/reference/eks/update-kubeconfig.html
    "--alias",
    alias,
    // The user-alias argument was added in AWS CLI v2.11.6
    "--user-alias",
    alias,
  ];

  try {
    // Federated access especially sometimes takes some time to propagate, so
    // retry for up to 20 seconds just in case it takes a while.
    const awsResult = await spinUntil(
      "Waiting for AWS resources to be provisioned and updating kubeconfig for EKS",
      retryWithSleep(
        async () => await exec("aws", updateKubeconfigArgs, { check: true }),
        {
          shouldRetry: (error: any) => {
            if (error?.stderr) {
              if (
                error.stderr.includes("Unknown options") ||
                error.stderr.includes("--user-alias")
              ) {
                print2(
                  "\nThe AWS CLI version is not compatible with the p0 kubeconfig command. Please update to at least version 2.11.6."
                );
                return false; // Stop retrying if the CLI version is incompatible
              }
            }
            return true;
          },
          retries: 8,
          delayMs: 2500,
        }
      )
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
      ["config", "use-context", alias],
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

/**
 * Validates that all required CLI tools are installed and available in PATH
 * This is called early, before authentication, so we check all possible tools
 * (kubectl, aws CLI, and gcloud CLI) since we don't know the provider yet.
 *
 * @param debug - Whether to print debug information
 * @throws Exits with code 1 if any required tool is not found
 */
const validateKubeconfigTools = async (debug?: boolean) => {
  const tools: Array<{ name: string; description: string }> = [
    { name: "kubectl", description: "Kubernetes command-line tool" },
    { name: "aws", description: "AWS CLI" },
    { name: "gcloud", description: "Google Cloud CLI" },
  ];

  for (const tool of tools) {
    try {
      // Use 'where' on Windows or 'which' on Unix
      const checkCommand = process.platform === "win32" ? "where" : "which";
      await asyncSpawn({ debug }, checkCommand, [tool.name]);
    } catch (error) {
      print2(`Error: ${tool.description} (${tool.name}) not found in PATH.`);
      print2(`Please install ${tool.description} and ensure it's in your PATH.`);
      sys.exit(1);
    }
  }
};

const extractClusterNameAndRegion = (clusterArn: string) => {
  const INVALID_ARN_MSG = `Invalid EKS cluster ARN: ${clusterArn}`;
  // Example EKS cluster ARN: arn:aws:eks:us-west-2:123456789012:cluster/my-testing-cluster
  const arn = parseArn(clusterArn);
  const { region: clusterRegion, resource: resourceStr } = arn;
  const [resourceType, clusterName] = resourceStr.split("/");

  if (resourceType !== "cluster" || !clusterName || !clusterRegion) {
    throw INVALID_ARN_MSG;
  }

  return { clusterRegion, clusterName };
};
