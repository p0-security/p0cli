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
import { assertNever, getAppName, exec } from "../../util";
import { getAwsConfig } from "../aws/config";
import { assumeRoleWithIdc } from "../aws/idc";
import { AwsCredentials } from "../aws/types";
import { parseArn } from "../aws/utils";
import { assumeRoleWithOktaSaml } from "../okta/aws";
import { ensureGcloudAuth, setGcloudProject } from "../google/auth";
import { gcloudCommandArgs } from "../google/util";
import { print2 } from "../../drivers/stdio";
import { K8sConfig, K8sPermissionSpec } from "./types";
import { pick } from "lodash";
import { sys } from "typescript";
import yargs from "yargs";

const KUBECONFIG_PREFIX = "p0";

export type AwsK8sConfig = {
  provider: "aws";
  clusterId: string;
  awsAccountId: string;
  awsClusterArn: string;
  awsLoginType: "federated" | "idc";
};

export type GcpK8sConfig = {
  provider: "gcp";
  clusterId: string;
  projectId?: string;
  zone?: string;
  clusterName?: string;
};

export type K8sIntegrationConfig = AwsK8sConfig | GcpK8sConfig;

export const getAndValidateK8sIntegration = async (
  authn: Authn,
  clusterId: string,
  debug?: boolean
): Promise<K8sIntegrationConfig> => {
  const configDoc = await fetchIntegrationConfig<{ config: K8sConfig }>(
    authn,
    "k8s",
    debug
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

  if (hosting.type === "aws") {
    const { arn: awsClusterArn } = hosting;
    const { accountId: awsAccountId } = parseArn(awsClusterArn);
    const { config: awsConfig } = await getAwsConfig(authn, awsAccountId, debug);
    const { login: awsLogin } = awsConfig;

    // Verify that the AWS auth type is supported before issuing the requests
    if (!awsLogin?.type || awsLogin?.type === "iam") {
      throw `This AWS account is not configured for kubectl access.\nYou can request access to the cluster using the \`${getAppName()} request k8s\` command.`;
    }

    return {
      provider: "aws",
      clusterId,
      awsAccountId,
      awsClusterArn,
      awsLoginType: awsLogin.type,
    };
  } else if (hosting.type === "gcp") {
    // Extract GCP cluster details from config
    const gcpHosting = hosting as any;
    const projectId = gcpHosting.project;
    // Location can be a zone (e.g., "us-east1-b") or region (e.g., "us-east1")
    // For get-credentials, we need the zone if it's a zonal cluster, or region if regional
    const location = gcpHosting.location;
    let zone: string | undefined;
    if (location) {
      if (typeof location === "string") {
        zone = location;
      } else if (location.region) {
        zone = location.region;
      } else if (location.zone) {
        zone = location.zone;
      }
    }
    const clusterName = gcpHosting.clusterName || clusterId;
    
    if (debug) {
      print2(`GCP cluster config - Project: ${projectId || "not found"}, Zone/Location: ${zone || "not found"}, Cluster: ${clusterName || "not found"}`);
    }
    
    return {
      provider: "gcp",
      clusterId,
      projectId,
      zone,
      clusterName,
    };
  } else {
    throw (
      `This command currently only supports AWS EKS and GCP GKE clusters, and ${clusterId} is not configured as one.\n` +
      `You can request access to the cluster using the \`${getAppName()} request k8s\` command.`
    );
  }
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
        ...(args.duration ? ["--duration", args.duration] : []),
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
  loginType: "federated" | "idc",
  debug?: boolean
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
      return await assumeRoleWithOktaSaml(
        authn,
        {
          accountId: awsAccountId,
          role: name,
        },
        debug
      );
    default:
      throw assertNever(loginType);
  }
};

/**
 * Extracts GCP GKE cluster information from the request response
 * 
 * @param request - The permission request response
 * @param clusterId - The cluster ID (used as cluster name if not found in response)
 * @param debug - Whether to print debug information
 * @returns GCP cluster details including project, zone, and cluster name
 */
const extractGcpClusterDetails = (
  request: PermissionRequest<K8sPermissionSpec>,
  clusterId: string,
  debug?: boolean
): { projectId: string; zone: string; clusterName: string } => {
  const { permission } = request;
  const perm = permission as any;
  const resource = permission.resource as any;

  // Extract project ID - check multiple possible locations
  const projectId = 
    perm.parent || 
    resource?.projectId || 
    perm.projectId ||
    resource?.project;

  // Extract zone - check multiple possible locations
  const zone = 
    perm.zone || 
    resource?.zone ||
    perm.location ||
    resource?.location;

  // Extract cluster name - use clusterId as fallback
  const clusterName = 
    perm.clusterName ||
    resource?.clusterName ||
    perm.cluster ||
    resource?.cluster ||
    clusterId;

  if (debug) {
    print2(`Extracting GCP cluster details - Project: ${projectId || "not found"}, Zone: ${zone || "not found"}, Cluster: ${clusterName || "not found"}`);
  }

  if (!projectId || !zone || !clusterName) {
    print2("Error: Missing required GCP GKE cluster details:");
    print2(`  Project ID: ${projectId || "missing"}`);
    print2(`  Zone: ${zone || "missing"}`);
    print2(`  Cluster Name: ${clusterName || "missing"}`);
    throw new Error("Could not extract GCP GKE cluster details from request response. Please ensure the cluster is properly configured.");
  }

  return {
    projectId: String(projectId),
    zone: String(zone),
    clusterName: String(clusterName),
  };
};

/**
 * Configures kubectl for a GCP GKE cluster
 * 
 * Authenticates with gcloud, sets the project, gets cluster credentials,
 * and sets the kubectl context.
 * 
 * @param request - The permission request response
 * @param clusterId - The cluster ID
 * @param integrationConfig - The integration config (may contain project/zone info)
 * @param debug - Whether to print debug information
 */
export const gcpKubeconfig = async (
  request: PermissionRequest<K8sPermissionSpec>,
  clusterId: string,
  integrationConfig: GcpK8sConfig,
  debug?: boolean
): Promise<void> => {
  // Try to extract GCP cluster details from request first, then fall back to integration config
  let projectId: string | undefined;
  let zone: string | undefined;
  let clusterName: string | undefined;
  
  try {
    const extracted = extractGcpClusterDetails(request, clusterId, debug);
    projectId = extracted.projectId;
    zone = extracted.zone;
    clusterName = extracted.clusterName;
  } catch (error) {
    // If extraction from request fails, try integration config
    if (debug) {
      print2("Using cluster details from integration config");
    }
    projectId = integrationConfig.projectId;
    zone = integrationConfig.zone;
    clusterName = integrationConfig.clusterName || clusterId;
  }
  
  // If still missing, try to query gcloud
  if (!projectId || !zone) {
    if (debug) {
      print2("Querying gcloud for missing cluster details...");
    }
    // Try to get project from gcloud config
    try {
      const { command, args } = gcloudCommandArgs(["config", "get-value", "project"]);
      const result = await exec(command, args, { check: false });
      if (result.stdout && !projectId) {
        projectId = result.stdout.trim();
        if (debug) {
          print2(`Using project from gcloud config: ${projectId}`);
        }
      }
      } catch (error) {
        // Silently continue if gcloud query fails
      }
    
    // If we have project but not zone, try to list clusters and find the one matching clusterId
    if (projectId && !zone && clusterName) {
      try {
        const { command, args } = gcloudCommandArgs([
          "container",
          "clusters",
          "list",
          "--project",
          projectId,
          "--format",
          "json",
        ]);
        const result = await exec(command, args, { check: false });
        if (result.stdout) {
          const clusters = JSON.parse(result.stdout);
          const cluster = clusters.find((c: any) => 
            c.name === clusterName || c.name === clusterId
          );
          if (cluster) {
            zone = cluster.zone || cluster.location;
            if (debug && zone) {
              print2(`Using zone from gcloud cluster list: ${zone}`);
            }
          }
        }
      } catch (error) {
        // Silently continue if gcloud query fails
      }
    }
  }
  
  // Final validation
  if (!projectId || !zone || !clusterName) {
    print2("Error: Missing required GCP GKE cluster details:");
    print2(`  Project ID: ${projectId || "missing"}`);
    print2(`  Zone: ${zone || "missing"}`);
    print2(`  Cluster Name: ${clusterName || "missing"}`);
    print2("\nPlease ensure:");
    print2("  1. The cluster is properly configured in P0 with project and zone information");
    print2("  2. You have gcloud configured with the correct project");
    print2("  3. The cluster exists and is accessible");
    throw new Error("Could not determine GCP GKE cluster details. Please check cluster configuration.");
  }

  // Ensure gcloud is authenticated
  await ensureGcloudAuth(debug);

  // Set the project
  await setGcloudProject(projectId, debug);

  // Get cluster credentials using gcloud
  print2(`Getting credentials for GKE cluster '${clusterName}'...`);
  const { command, args } = gcloudCommandArgs([
    "container",
    "clusters",
    "get-credentials",
    clusterName,
    "--zone",
    zone,
    "--project",
    projectId,
  ]);

  try {
    const result = await exec(command, args, { check: true });
    if (result.stdout) {
      print2(result.stdout);
    }
  } catch (error: any) {
    print2(`Failed to invoke \`gcloud container clusters get-credentials\``);
    if (error.stderr) {
      print2(error.stderr);
    }
    throw error;
  }

  // Set kubectl context to the cluster
  // gcloud get-credentials typically sets the context automatically, but we'll set it explicitly
  // The context name format is typically: gke_<project>_<zone>_<cluster-name>
  const contextName = `gke_${projectId}_${zone}_${clusterName}`;
  
  try {
    const kubectlResult = await exec(
      "kubectl",
      ["config", "use-context", contextName],
      { check: true }
    );
    if (kubectlResult.stdout) {
      print2(kubectlResult.stdout);
    }
  } catch (error: any) {
    // If setting context fails, it might already be set or have a different name
    // This is not critical, so we'll just log it in debug mode
    if (debug) {
      print2(`Note: Could not set kubectl context to '${contextName}'. It may already be set or have a different name.`);
      if (error.stderr) {
        print2(error.stderr);
      }
    }
  }
};
