/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { decodeProvisionStatus } from "./shared";
import { request } from "./shared/request";
import { authenticate } from "../drivers/auth";
import { print2 } from "../drivers/stdio";
import { getAppName } from "../util";
import { PsqlCommandArgs, PsqlPermissionSpec } from "../types/psql";
import { PermissionRequest } from "../types/request";
import { Authn } from "../types/identity";
import { pick } from "lodash";
import yargs from "yargs";
import { asyncSpawn } from "../common/subprocess";
import { createCleanChildEnv, spawnWithCleanEnv } from "../util";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { sys } from "typescript";
import { ChildProcess } from "node:child_process";
import { fetchCommand, fetchIntegrationConfig } from "../drivers/api";
import { getTenantConfig } from "../drivers/config";
import { defaultConfig } from "../drivers/env";
import { gcloudCommandArgs } from "../plugins/google/util";

export const psqlCommand = (yargs: yargs.Argv) =>
  yargs.command<PsqlCommandArgs>(
    "psql <destination>",
    "Connect to an RDS Postgres database via IAM authentication",
    (yargs) =>
      yargs
        .positional("destination", {
          type: "string",
          demandOption: true,
          describe: "The RDS Postgres instance name",
        })
        .option("role", {
          type: "string",
          demandOption: true,
          describe: "The AWS IAM SSO role name to use",
        })
        .option("reason", {
          describe: "Reason access is needed",
          type: "string",
        })
        .option("duration", {
          type: "string",
          describe:
            "Requested duration for access (format like '10 minutes', '2 hours', '5 days', or '1 week')",
        })
        .option("debug", {
          type: "boolean",
          describe: "Print debug information.",
          default: false,
        })
        .usage("$0 psql <destination> --role <ROLE_NAME>")
        .epilogue(
          `Connect to an RDS Postgres database using AWS SSO IAM authentication.

Example:
  $ ${getAppName()} psql my-rds-instance --role MyRole --reason "Need to debug production issue"`
        ),
    psqlAction
  );

/**
 * Connect to an RDS Postgres database via IAM authentication
 *
 * Implicitly requests access to the database if not already granted.
 * Automatically configures AWS SSO and generates IAM auth tokens.
 */
const psqlAction = async (args: yargs.ArgumentsCamelCase<PsqlCommandArgs>) => {
  // Validate psql is installed (required for both providers)
  // We'll validate provider-specific tools after we know the provider
  try {
    const checkCommand = process.platform === "win32" ? "where" : "which";
    await asyncSpawn({ debug: args.debug }, checkCommand, ["psql"]);
  } catch (error) {
    print2("Error: PostgreSQL client (psql) not found in PATH.");
    print2("Please install PostgreSQL client and ensure it's in your PATH.");
    sys.exit(1);
  }

  const authn = await authenticate(args);

  // Make request and wait for approval
  const response = await provisionRequest(authn, args);
  if (!response || !response.request) {
    sys.exit(1);
  }

  // TypeScript doesn't recognize sys.exit() as a return, so use non-null assertion
  const provisionedRequest = response!.request!;

  // Get user email for database username (after we have the request)
  const dbUserResult = await getUserEmail(authn, provisionedRequest, args.debug);
  if (!dbUserResult) {
    print2("Error: Could not determine user email for database authentication.");
    sys.exit(1);
  }
  const dbUser: string = dbUserResult!;

  // Extract connection details from the request
  // Also try to query backend for instance details if endpoint is missing
  const connectionDetailsResult = await extractConnectionDetails(
    provisionedRequest, 
    args.role, 
    args.debug,
    authn,
    args
  );
  if (!connectionDetailsResult) {
    print2("Error: Could not extract connection details from request response.");
    sys.exit(1);
  }
  const connectionDetails: ConnectionDetails = connectionDetailsResult!;

  // Route to provider-specific connection flow
  if (connectionDetails.provider === "gcp") {
    // GCP CloudSQL connection flow
    // Validate gcloud is installed
    await validateCliTools("gcp", args.debug);
    await connectToCloudSQL(connectionDetails, dbUser, args.debug);
  } else {
    // AWS RDS connection flow (existing)
    // Validate aws CLI is installed
    await validateCliTools("aws", args.debug);
    // Configure AWS SSO profile
    const profileName = await configureAwsSsoProfile(connectionDetails, args.debug);

    // Login to AWS SSO
    await loginAwsSso(profileName, args.debug);

    // Only try to get actual RDS endpoint from AWS if the current endpoint looks like it was constructed
    // (i.e., it's in the format instance.region.rds.amazonaws.com without the random ID)
    // If we already have the full endpoint from the integration config, don't overwrite it
    const hostParts = connectionDetails.rdsHost.split(".");
    const isConstructedEndpoint = hostParts.length === 4 && 
      hostParts[1] === connectionDetails.region && 
      hostParts[2] === "rds" && 
      hostParts[3] === "amazonaws.com";
    
    if (isConstructedEndpoint) {
      // This looks like a constructed endpoint, try to get the actual one from AWS
      const instanceIdentifier = hostParts[0] || connectionDetails.rdsHost;
      const actualRdsHost = await getRdsEndpoint(
        instanceIdentifier,
        connectionDetails.region,
        profileName,
        args.debug
      );
      if (actualRdsHost && actualRdsHost !== connectionDetails.rdsHost) {
        connectionDetails.rdsHost = actualRdsHost;
        if (args.debug) {
          print2(`Updated RDS endpoint to: ${actualRdsHost}`);
        }
      }
    } else {
      if (args.debug) {
        print2(`Using RDS endpoint from integration config: ${connectionDetails.rdsHost}`);
      }
    }

    // Generate IAM auth token
    const token = await generateDbAuthToken(
      connectionDetails,
      dbUser,
      profileName,
      args.debug
    );

    // Connect to database
    await connectToDatabase(connectionDetails, dbUser, token, args.debug);
  }

  // Force exit to prevent hanging
  if (process.env.NODE_ENV !== "unit") {
    process.exit(0);
  }
};

const validateCliTools = async (provider?: "aws" | "gcp", debug?: boolean) => {
  const tools: Array<{ name: string; description: string }> = [
    { name: "psql", description: "PostgreSQL client" },
  ];

  // Add provider-specific tools
  if (provider === "gcp") {
    tools.push({ name: "gcloud", description: "Google Cloud CLI" });
  } else {
    // Default to AWS if not specified
    tools.push({ name: "aws", description: "AWS CLI" });
  }

  for (const tool of tools) {
    try {
      // Use 'command -v' on Unix or 'where' on Windows, but 'which' works on most systems
      const checkCommand = process.platform === "win32" ? "where" : "which";
      await asyncSpawn({ debug }, checkCommand, [tool.name]);
    } catch (error) {
      print2(`Error: ${tool.description} (${tool.name}) not found in PATH.`);
      print2(`Please install ${tool.description} and ensure it's in your PATH.`);
      sys.exit(1);
    }
  }
};

const getUserEmail = async (
  authn: Authn,
  request?: PermissionRequest<PsqlPermissionSpec>,
  debug?: boolean
): Promise<string | null> => {
  // First, check if the backend provided username in the generated field
  if (request?.generated?.username) {
    if (debug) {
      print2(`Using username from request: ${request.generated.username}`);
    }
    return request.generated.username;
  }

  // Fallback to user email from authentication
  if (authn.userCredential?.user?.email) {
    if (debug) {
      print2(`Using user email: ${authn.userCredential.user.email}`);
    }
    return authn.userCredential.user.email;
  }

  // Try to extract from principal field in request
  if (request?.principal) {
    if (debug) {
      print2(`Using principal from request: ${request.principal}`);
    }
    return request.principal;
  }

  if (debug) {
    print2("Could not determine username for database authentication");
  }
  return null;
};

const provisionRequest = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<PsqlCommandArgs>
) => {
  const { destination, role } = args;

  const makeRequest = async () => {
    return await request("request")<PermissionRequest<PsqlPermissionSpec>>(
      {
        ...pick(args, "$0", "_"),
        arguments: [
          "pg",
          "role",
          destination,
          role,
          ...(args.reason ? ["--reason", args.reason] : []),
          ...(args.duration ? ["--duration", args.duration] : []),
        ],
        wait: true,
        debug: args.debug,
      },
      authn,
      { message: "approval-required" }
    );
  };

  const response = await makeRequest();

  if (!response) {
    print2("Did not receive access ID from server");
    return null;
  }

  const { isPreexisting } = response;

  const message = isPreexisting
    ? "Existing access found. Connecting to database."
    : "Waiting for access to be provisioned";
  print2(message);

  const result = await decodeProvisionStatus<PsqlPermissionSpec>(response.request);

  if (!result) {
    // Check if the error is about public IP requirement for CloudSQL
    const errorMessage = response.request?.error?.message || "";
    if (
      errorMessage.includes("does not have a public IP address") &&
      errorMessage.includes("Cloud SQL")
    ) {
      print2("");
      print2(
        "Note: The Cloud SQL Proxy (which this CLI uses) supports private IP instances."
      );
      print2(
        "This error is due to a backend limitation that requires a public IP."
      );
      print2(
        "Please contact your P0 administrator to update the backend to support private IP CloudSQL instances."
      );
    }
    return null;
  }

  return {
    request: response.request,
  };
};

type AwsConnectionDetails = {
  provider: "aws";
  rdsHost: string;
  region: string;
  port: number;
  database: string;
  ssoStartUrl: string;
  ssoRegion: string;
  ssoAccountId: string;
  roleName: string;
};

type GcpConnectionDetails = {
  provider: "gcp";
  projectId: string;
  instanceConnectionName: string;
  region: string;
  port: number;
  database: string;
  instanceName: string;
  publicIp?: string; // Public IP address for direct connection
};

type ConnectionDetails = AwsConnectionDetails | GcpConnectionDetails;

const extractConnectionDetails = async (
  request: PermissionRequest<PsqlPermissionSpec>,
  roleName: string,
  debug?: boolean,
  authn?: any,
  args?: any
): Promise<ConnectionDetails | null> => {
  try {
    const { permission, generated } = request;
    const perm = permission as any;
    const resource = permission.resource as any;

    // Detect provider FIRST before extracting provider-specific fields
    const integrationType = perm.integrationType || resource.integrationType;
    const instancePath = perm.instance || "";
    const isGcp = 
      integrationType === "cloudsql" ||
      integrationType === "cloud-sql" ||
      instancePath.toLowerCase().startsWith("cloud-sql/") ||
      instancePath.toLowerCase().includes("cloudsql") ||
      (resource as any)?.provider === "gcp" ||
      (resource as any)?.type === "gcp";
    
    if (debug) {
      print2(`Detected provider: ${isGcp ? "GCP CloudSQL" : "AWS RDS"}`);
      print2(`Integration type: ${integrationType || "not specified"}`);
      print2(`Instance path: ${instancePath || "not specified"}`);
    }

    // Extract common fields - for GCP, fields are in permission, for AWS they may be in resource
    const region = perm.region || resource?.region;
    const databaseName = perm.databaseName || resource?.databaseName;
    const instanceName = perm.instanceName || resource?.instanceName;
    
    // Extract provider-specific fields only if needed
    const accountId = isGcp ? undefined : (resource?.accountId || resource?.account || perm.parent);
    const idcId = isGcp ? undefined : resource?.idcId;
    const idcRegion = isGcp ? undefined : (resource?.idcRegion || resource?.idc_region || region);
    
    // Default port for PostgreSQL - check both permission and resource
    const port = perm.port || resource?.port || 5432;

    // Extract permission set name from generated resource (only for AWS)
    // The permission set name is in generated.resource.name
    const gen = generated as any;
    const permissionSetName = gen?.resource?.name || gen?.permissionSet || roleName;
    
    if (debug && !isGcp) {
      print2(`Using permission set name: ${permissionSetName}`);
    }

    if (debug) {
      print2("=== Debug: Full response structure ===");
      print2("Full request object:");
      print2(JSON.stringify(request, null, 2));
      print2("\nFull permission object:");
      print2(JSON.stringify(permission, null, 2));
      print2("\nFull resource object:");
      print2(JSON.stringify(resource, null, 2));
      print2("\nFull generated object:");
      print2(JSON.stringify(generated, null, 2));
      print2("=== End debug ===");
    }

    // Route to provider-specific extraction
    if (isGcp) {
      return await extractGcpConnectionDetails(
        perm,
        resource,
        region,
        databaseName,
        instanceName,
        port,
        debug,
        authn,
        args
      );
    } else {
      return await extractAwsConnectionDetails(
        perm,
        resource,
        region,
        databaseName,
        instanceName,
        accountId,
        idcId,
        idcRegion,
        port,
        roleName,
        generated,
        debug,
        authn,
        args
      );
    }
  } catch (error) {
    print2(`Error extracting connection details: ${error}`);
    if (debug) {
      print2(`Stack: ${error instanceof Error ? error.stack : String(error)}`);
    }
    return null;
  }
};

const extractGcpConnectionDetails = async (
  perm: any,
  resource: any,
  region: string,
  databaseName: string,
  instanceName: string,
  port: number,
  debug?: boolean,
  _authn?: any,
  _args?: any
): Promise<GcpConnectionDetails | null> => {
  // Extract GCP-specific fields - for GCP, fields are typically in permission object
  const projectId = perm.parent || resource?.projectId || perm.projectId;
  
  if (!region || !databaseName || !projectId || !instanceName) {
    print2("Error: Missing required GCP CloudSQL connection details:");
    print2(`  Region: ${region || "missing"}`);
    print2(`  Database: ${databaseName || "missing"}`);
    print2(`  Project ID: ${projectId || "missing"}`);
    print2(`  Instance Name: ${instanceName || "missing"}`);
    return null;
  }

  // Get instance connection name - format: project-id:region:instance-name
  // Check permission first (where GCP fields typically are), then resource
  let instanceConnectionName = 
    perm.instanceConnectionName ||
    perm.connectionName ||
    perm.connection_name ||
    resource?.instanceConnectionName ||
    resource?.connectionName ||
    resource?.connection_name;
  
  if (!instanceConnectionName) {
    // Construct from project:region:instance
    instanceConnectionName = `${projectId}:${region}:${instanceName}`;
    if (debug) {
      print2(`Constructed instance connection name: ${instanceConnectionName}`);
    }
  } else {
    if (debug) {
      print2(`Using instance connection name from backend: ${instanceConnectionName}`);
    }
  }

  // Ensure port is a number
  const portNum = typeof port === "number" ? port : parseInt(String(port), 10);
  if (isNaN(portNum) || portNum <= 0) {
    print2(`Error: Invalid port number: ${port}`);
    return null;
  }

  // Try to get public IP if available (will be queried later if not provided)
  const publicIp = 
    perm.publicIp ||
    resource?.publicIp ||
    perm.ipAddress ||
    resource?.ipAddress ||
    undefined;

  return {
    provider: "gcp",
    projectId: String(projectId),
    instanceConnectionName: String(instanceConnectionName),
    region: String(region),
    port: portNum,
    database: String(databaseName),
    instanceName: String(instanceName),
    publicIp: publicIp ? String(publicIp) : undefined,
  };
};

const extractAwsConnectionDetails = async (
  perm: any,
  resource: any,
  region: string,
  databaseName: string,
  instanceName: string,
  accountId: string,
  idcId: string,
  idcRegion: string,
  port: number,
  roleName: string,
  generated: any,
  debug?: boolean,
  authn?: any,
  args?: any
): Promise<AwsConnectionDetails | null> => {
  if (!region || !databaseName || !accountId || !idcId || !idcRegion) {
    print2("Error: Missing required AWS RDS connection details in request response:");
    print2(`  Region: ${region || "missing"}`);
    print2(`  Database: ${databaseName || "missing"}`);
    print2(`  Account ID: ${accountId || "missing"}`);
    print2(`  IDC ID: ${idcId || "missing"}`);
    print2(`  IDC Region: ${idcRegion || "missing"}`);
    if (debug) {
      print2("Full permission object:");
      print2(JSON.stringify(perm, null, 2));
    }
    return null;
  }

    // Get SSO Start URL - check if backend provides it, otherwise construct from IDC ID
    // The backend might provide ssoStartUrl directly, or we construct it
    let ssoStartUrl = 
      (resource as any).ssoStartUrl ||
      (resource as any).sso_start_url ||
      (resource as any).ssoStartURL ||
      (perm as any).ssoStartUrl;
    
    if (!ssoStartUrl) {
      // Construct SSO Start URL from IDC ID (similar to AWS IDC code)
      // Format: https://{idcId}.awsapps.com/start or https://start.us-gov-home.awsapps.com/directory/{idcId} for gov regions
      ssoStartUrl = idcRegion.includes("us-gov")
        ? `https://start.us-gov-home.awsapps.com/directory/${idcId}`
        : `https://${idcId}.awsapps.com/start`;
      if (debug) {
        print2(`Constructed SSO Start URL from IDC ID: ${ssoStartUrl}`);
      }
    } else {
      if (debug) {
        print2(`Using SSO Start URL from backend: ${ssoStartUrl}`);
      }
    }

    // Get RDS endpoint - check if backend provides it first
    // Check multiple possible locations in the response - search deeply
    let rdsHost = 
      // Check in resource object
      (resource as any).rdsHost ||
      (resource as any).hostname ||
      (resource as any).endpoint ||
      (resource as any).host ||
      (resource as any).address ||
      (resource as any).dbEndpoint ||
      (resource as any).dbHost ||
      (resource as any).connectionString ||
      (resource as any).connection?.host ||
      (resource as any).connection?.endpoint ||
      (resource as any).connection?.hostname ||
      // Check in permission object
      (perm as any).rdsHost ||
      (perm as any).endpoint ||
      (perm as any).hostname ||
      (perm as any).host ||
      (perm as any).address ||
      (perm as any).dbEndpoint ||
      (perm as any).dbHost ||
      (perm as any).connectionString ||
      (perm as any).connection?.host ||
      (perm as any).connection?.endpoint ||
      (perm as any).connection?.hostname ||
      // Check in generated object (passed as parameter)
      (generated as any)?.rdsHost ||
      (generated as any)?.endpoint ||
      (generated as any)?.hostname ||
      (generated as any)?.connectionString ||
      (generated as any)?.connection?.host ||
      (generated as any)?.connection?.endpoint ||
      (generated as any)?.connection?.hostname;
    
    // If backend doesn't provide it, we'll need to query AWS or construct it
    if (!rdsHost) {
      // Extract DB instance identifier from ARN or instance name
      // The ARN format is: arn:aws:rds-db:region:account-id:dbuser:db-instance-id/db-user-name
      // Example: arn:aws:rds-db:us-east-2:326061184090:dbuser:db-7LYIFFGO2QKFIRJJT2NRKPO2DE/michael.security@workspace.got.network
      let dbInstanceIdentifier: string | null = null;
      
      // Try to extract from ARN first (most reliable)
      const arn = resource.arn;
      if (arn && typeof arn === "string" && arn.includes(":dbuser:")) {
        // Format: arn:aws:rds-db:region:account:dbuser:db-instance-id/db-user
        const arnParts = arn.split(":dbuser:");
        if (arnParts.length === 2 && arnParts[1]) {
          const dbUserPart = arnParts[1];
          const dbInstancePart = dbUserPart.split("/")[0];
          if (dbInstancePart) {
            dbInstanceIdentifier = dbInstancePart;
            if (debug) {
              print2(`Extracted DB instance identifier from ARN: ${dbInstanceIdentifier}`);
            }
          }
        }
      }
      
      // Fallback to instance name if ARN extraction failed
      if (!dbInstanceIdentifier) {
        const instance = perm.instance || instanceName;
        dbInstanceIdentifier = instanceName;
        
        // Parse instance identifier from full instance path if needed
        if (instance && typeof instance === "string") {
          // Format: rds/account/account:region:instance-name/db-name
          const parts = instance.split("/");
          if (parts.length >= 3) {
            const instancePart = parts[2];
            if (instancePart) {
              const instanceParts = instancePart.split(":");
              if (instanceParts.length >= 3 && instanceParts[2]) {
                dbInstanceIdentifier = instanceParts[2];
              }
            }
          }
        }
        
        if (debug && dbInstanceIdentifier) {
          print2(`Using instance name as DB instance identifier: ${dbInstanceIdentifier}`);
        }
      }

      if (!dbInstanceIdentifier) {
        print2("Error: Could not determine RDS instance identifier");
        return null;
      }

      // Try to query backend for instance details to get the endpoint
      if (authn && args) {
        const fullInstancePath = perm.instance || instanceName;
        const queriedEndpoint = await queryBackendForEndpoint(
          instanceName,
          region,
          authn,
          args,
          debug,
          fullInstancePath,
          accountId
        );
        if (queriedEndpoint) {
          rdsHost = queriedEndpoint;
          if (debug) {
            print2(`Retrieved RDS endpoint from backend: ${rdsHost}`);
          }
        } else {
          // Fallback: try to fetch RDS endpoint (will construct it if query fails, actual endpoint will be fetched after SSO login)
          rdsHost = await getRdsEndpoint(dbInstanceIdentifier, region, undefined, debug);
        }
      } else {
        // Fallback: try to fetch RDS endpoint (will construct it if query fails, actual endpoint will be fetched after SSO login)
        rdsHost = await getRdsEndpoint(dbInstanceIdentifier, region, undefined, debug);
      }
    } else {
      if (debug) {
        print2(`Using RDS endpoint from backend: ${rdsHost}`);
      }
    }

    if (!rdsHost) {
      print2("Error: Could not retrieve RDS endpoint from AWS");
      return null;
    }

    // Ensure port is a number
    const portNum = typeof port === "number" ? port : parseInt(String(port), 10);
    if (isNaN(portNum) || portNum <= 0) {
      print2(`Error: Invalid port number: ${port}`);
      return null;
    }

    // Extract permission set name from generated resource
    const permissionSetName = generated?.resource?.name || generated?.permissionSet || roleName;
    
    if (debug) {
      print2(`Using permission set name: ${permissionSetName}`);
    }

    return {
      provider: "aws",
      rdsHost: rdsHost.trim(),
      region: String(region),
      port: portNum,
      database: String(databaseName),
      ssoStartUrl,
      ssoRegion: String(idcRegion),
      ssoAccountId: String(accountId),
      roleName: permissionSetName, // Use permission set name from response, not user-provided role
    };
};

const queryBackendForEndpoint = async (
  instanceName: string,
  _region: string,
  authn: Authn,
  args: any,
  debug?: boolean,
  fullInstancePath?: string,
  _accountId?: string
): Promise<string | null> => {
  try {
    if (debug) {
      print2(`Querying backend for instance details: ${instanceName}`);
      if (fullInstancePath) {
        print2(`Using full instance path: ${fullInstancePath}`);
      }
    }

    // Try multiple query approaches to get instance details
    let response: any = null;

    // Approach 1: Try querying integration config for pg/rds to get endpoint
    // The endpoint is stored in config.access-management.{instance-name}.installType.hostname
    try {
      if (debug) {
        print2("Trying to fetch integration config for pg/rds...");
      }
      // Try both "pg" and "rds" as integration names
      for (const integrationName of ["pg", "rds"]) {
        try {
          const config = await fetchIntegrationConfig<any>(authn, integrationName, debug);
          if (config && typeof config === "object" && config.config) {
            const integrationConfig = config.config;
            
            // The endpoint is typically at: config.access-management.{instance-name}.installType.hostname
            // Try to find it by searching for the instance name in access-management
            if (integrationConfig["access-management"] && typeof integrationConfig["access-management"] === "object") {
              const accessManagement = integrationConfig["access-management"];
              
              // Try to find instance by name (could be exact match or partial)
              for (const [key, value] of Object.entries(accessManagement)) {
                if (value && typeof value === "object" && (value as any).installType) {
                  const installType = (value as any).installType;
                  const hostname = installType?.hostname;
                  if (hostname && typeof hostname === "string") {
                    // Check if this instance matches our instance name
                    // The key might be the instance name or a variation
                    if (key.includes(instanceName) || instanceName.includes(key) || 
                        (fullInstancePath && (key.includes(instanceName) || fullInstancePath.includes(key)))) {
                      if (debug) {
                        print2(`Found endpoint in integration config for instance '${key}': ${hostname}`);
                      }
                      return hostname;
                    }
                  }
                }
              }
              
              // If no exact match, try to find any hostname that looks like an RDS endpoint
              // and matches our instance name pattern
              const searchForEndpoint = (obj: any): string | null => {
                if (!obj || typeof obj !== "object") return null;
                for (const [key, value] of Object.entries(obj)) {
                  if (typeof value === "string" && value.includes(".rds.amazonaws.com")) {
                    // Check if this endpoint matches our instance name
                    const endpointParts = value.split(".");
                    const endpointInstanceName = endpointParts[0] || "";
                    if (value.includes(instanceName) || instanceName.includes(endpointInstanceName)) {
                      if (debug) {
                        print2(`Found matching RDS endpoint: ${value}`);
                      }
                      return value;
                    }
                  }
                  if (typeof value === "object" && value !== null) {
                    const found = searchForEndpoint(value);
                    if (found) return found;
                  }
                }
                return null;
              };
              
              const foundEndpoint = searchForEndpoint(accessManagement);
              if (foundEndpoint) {
                return foundEndpoint;
              }
            }
            
            // Fallback: search entire config for any RDS endpoint
            if (debug) {
              print2("Searching entire integration config for RDS endpoint...");
            }
            const searchForEndpoint = (obj: any): string | null => {
              if (!obj || typeof obj !== "object") return null;
              for (const [key, value] of Object.entries(obj)) {
                if (typeof value === "string" && value.includes(".rds.amazonaws.com")) {
                  if (debug) {
                    print2(`Found RDS endpoint in config: ${value}`);
                  }
                  return value;
                }
                if (typeof value === "object" && value !== null) {
                  const found = searchForEndpoint(value);
                  if (found) return found;
                }
              }
              return null;
            };
            
            const foundEndpoint = searchForEndpoint(integrationConfig);
            if (foundEndpoint) {
              return foundEndpoint;
            }
          }
        } catch (error) {
          if (debug) {
            print2(`Failed to fetch integration config for ${integrationName}: ${error}`);
          }
        }
      }
    } catch (error) {
      if (debug) {
        print2(`Integration config query failed: ${error}`);
      }
    }

    // Approach 2: Query using the full instance path via command
    if (fullInstancePath) {
      try {
        if (debug) {
          print2(`Trying query with full instance path: ${fullInstancePath}`);
        }
        // Try querying with the full path - maybe the backend can resolve it
        response = await fetchCommand<any>(
          authn,
          args,
          ["ls", "pg", "role", "instance", fullInstancePath, "--json"]
        );
        if (response && response.items && response.items.length > 0) {
          if (debug) {
            print2("Got response with full instance path query");
          }
        }
      } catch (error) {
        if (debug) {
          print2(`Query with full path failed: ${error}`);
        }
      }
    }

    // Approach 3: Query using just the instance name
    if (!response || !response.items || response.items.length === 0) {
      try {
        if (debug) {
          print2(`Trying query with instance name: ${instanceName}`);
        }
        response = await fetchCommand<any>(
          authn,
          args,
          ["ls", "pg", "role", "instance", instanceName, "--json"]
        );
      } catch (error) {
        if (debug) {
          print2(`Query with instance name failed: ${error}`);
        }
      }
    }

    // Approach 4: Try querying for resource details using the instance identifier
    // Maybe there's a "describe" or "get" command
    if (!response || !response.items || response.items.length === 0) {
      try {
        if (debug) {
          print2("Trying alternative query approaches...");
        }
        // Try different query formats
        const alternativeQueries = [
          ["ls", "pg", "instance", instanceName, "--json"],
          ["ls", "pg", "resource", instanceName, "--json"],
          ["ls", "pg", instanceName, "--json"],
        ];
        
        for (const query of alternativeQueries) {
          try {
            response = await fetchCommand<any>(authn, args, query);
            if (response && response.items && response.items.length > 0) {
              if (debug) {
                print2(`Got response with query: ${query.join(" ")}`);
              }
              break;
            }
          } catch (error) {
            // Continue to next query
          }
        }
      } catch (error) {
        if (debug) {
          print2(`Alternative queries failed: ${error}`);
        }
      }
    }

    if (response && response.items && Array.isArray(response.items)) {
      // Look for endpoint in the response items
      for (const item of response.items) {
        if (item.value && typeof item.value === "string") {
          // Check if the value looks like an RDS endpoint
          if (item.value.includes(".rds.amazonaws.com")) {
            if (debug) {
              print2(`Found RDS endpoint in backend response: ${item.value}`);
            }
            return item.value;
          }
        }
        // Also check item.key
        if (item.key && typeof item.key === "string" && item.key.includes(".rds.amazonaws.com")) {
          if (debug) {
            print2(`Found RDS endpoint in backend response (key): ${item.key}`);
          }
          return item.key;
        }
      }
    }

    // Also check if response has endpoint field directly
    if (response && typeof response === "object") {
      const endpointFields = [
        "endpoint",
        "rdsHost",
        "hostname",
        "host",
        "address",
        "dbEndpoint",
        "dbHost",
      ];
      for (const field of endpointFields) {
        if ((response as any)[field] && typeof (response as any)[field] === "string") {
          const value = (response as any)[field];
          if (value.includes(".rds.amazonaws.com") || value.includes(".")) {
            if (debug) {
              print2(`Found RDS endpoint in backend response (${field}): ${value}`);
            }
            return value;
          }
        }
      }
    }

    if (debug) {
      print2("Backend response structure:");
      print2(JSON.stringify(response, null, 2));
    }
  } catch (error) {
    if (debug) {
      print2(`Failed to query backend for endpoint: ${error}`);
    }
  }

  return null;
};

const getRdsEndpoint = async (
  dbInstanceIdentifier: string,
  region: string,
  profileName?: string,
  debug?: boolean
): Promise<string | null> => {
  // If we have a profile (credentials), query AWS RDS for the actual endpoint
  if (profileName) {
    try {
      if (debug) {
        print2(`Querying AWS RDS for endpoint of instance: ${dbInstanceIdentifier}`);
      }

      // Try querying by DB instance identifier first
      try {
        const result = await asyncSpawn(
          { debug },
          "aws",
          [
            "rds",
            "describe-db-instances",
            "--db-instance-identifier",
            dbInstanceIdentifier,
            "--region",
            region,
            "--profile",
            profileName,
            "--query",
            "DBInstances[0].Endpoint.Address",
            "--output",
            "text",
          ]
        );

        const endpoint = result.trim();
        if (endpoint && endpoint !== "None" && !endpoint.includes("error")) {
          if (debug) {
            print2(`Retrieved RDS endpoint from AWS: ${endpoint}`);
          }
          return endpoint;
        }
      } catch (error) {
        // If query by identifier fails, try listing all instances and finding by name
        if (debug) {
          print2(`Query by identifier failed, trying to list instances...`);
        }
        // Note: This might fail due to permissions, but worth trying
      }
    } catch (error) {
      if (debug) {
        print2(`Failed to query AWS RDS for endpoint: ${error}`);
        print2("Falling back to constructed endpoint");
      }
    }
  }

  // Fallback: construct endpoint from instance identifier
  // Note: This may not work if the actual endpoint format is different
  // RDS endpoints typically follow: {instance-name}.{random-id}.{region}.rds.amazonaws.com
  // But we only have the instance identifier, so we try the simple format first
  const constructedEndpoint = `${dbInstanceIdentifier}.${region}.rds.amazonaws.com`;

  if (debug) {
    print2(`Using constructed RDS endpoint: ${constructedEndpoint}`);
    print2(`(Instance identifier: ${dbInstanceIdentifier})`);
    print2(`Note: If connection fails, the endpoint may need to be provided by the backend.`);
  }

  return constructedEndpoint;
};

const configureAwsSsoProfile = async (
  details: AwsConnectionDetails,
  debug?: boolean
): Promise<string> => {
  const awsConfigDir = path.join(os.homedir(), ".aws");
  const awsConfigPath = path.join(awsConfigDir, "config");

  // Ensure .aws directory exists
  if (!fs.existsSync(awsConfigDir)) {
    fs.mkdirSync(awsConfigDir, { recursive: true });
  }

  // Create unique profile name
  const timestamp = Date.now();
  const profileName = `p0-psql-${timestamp}`;
  const sessionName = `${profileName}-sso-session`;

  // Create SSO session block
  const sessionBlock = `[sso-session ${sessionName}]
sso_start_url = ${details.ssoStartUrl}
sso_region = ${details.ssoRegion}
sso_registration_scopes = sso:account:access

`;

  // Create profile block
  const profileBlock = `[profile ${profileName}]
sso_session = ${sessionName}
sso_account_id = ${details.ssoAccountId}
sso_role_name = ${details.roleName}
region = ${details.region}
output = json

`;

  // Append to config file
  const configContent = sessionBlock + profileBlock;
  fs.appendFileSync(awsConfigPath, configContent);

  if (debug) {
    print2(`Configured AWS SSO profile: ${profileName}`);
    print2(`Appended to ${awsConfigPath}`);
  }

  return profileName;
};

const loginAwsSso = async (profileName: string, debug?: boolean): Promise<void> => {
  print2(`Logging in to AWS SSO with profile ${profileName}...`);

  try {
    await asyncSpawn({ debug }, "aws", ["sso", "login", "--profile", profileName]);
    print2("AWS SSO login successful.");
  } catch (error) {
    print2(`Error: AWS SSO login failed. ${error}`);
    print2("Please check your SSO configuration or browser login.");
    throw error;
  }
};

const generateDbAuthToken = async (
  details: AwsConnectionDetails,
  dbUser: string,
  profileName: string,
  debug?: boolean
): Promise<string> => {
  print2(`Generating IAM auth token for user '${dbUser}'...`);

  try {
    const token = await asyncSpawn(
      { debug },
      "aws",
      [
        "rds",
        "generate-db-auth-token",
        "--hostname",
        details.rdsHost,
        "--port",
        String(details.port),
        "--region",
        details.region,
        "--username",
        dbUser,
        "--profile",
        profileName,
      ]
    );

    const trimmedToken = token.trim();
    if (!trimmedToken) {
      throw new Error("Failed to generate DB auth token: empty response");
    }

    if (debug) {
      print2("Token generated successfully.");
    }

    return trimmedToken;
  } catch (error) {
    print2(`Error: Failed to generate DB auth token. ${error}`);
    throw error;
  }
};

const connectToDatabase = async (
  details: AwsConnectionDetails,
  dbUser: string,
  token: string,
  debug?: boolean
): Promise<void> => {
  print2("Connecting to database...");
  print2("");

  const connectionString = `host=${details.rdsHost} port=${details.port} dbname=${details.database} user=${dbUser} sslmode=require`;

  // Set PGPASSWORD environment variable
  const env = { ...process.env, PGPASSWORD: token };

  try {
    // Use spawn to connect to psql interactively
    // psql accepts connection string as a single argument
    const child = spawnWithCleanEnv("psql", [connectionString], {
      stdio: "inherit",
      env: createCleanChildEnv(env),
    });

    child.on("error", (error: Error) => {
      print2(`Error: Failed to launch psql. ${error.message}`);
      print2("Make sure psql is installed and in your PATH.");
      sys.exit(1);
    });

    // Wait for the process to exit
    await new Promise<void>((resolve, reject) => {
      child.on("exit", (code) => {
        if (code === 0 || code === null) {
          resolve();
        } else {
          if (debug) {
            print2(`psql exited with code ${code}`);
          }
          // Don't reject on non-zero exit - user may have exited psql normally
          resolve();
        }
      });

      child.on("error", (error) => {
        reject(error);
      });
    });
  } catch (error) {
    print2(`Error: Failed to connect to database. ${error}`);
    throw error;
  }
};

const connectToCloudSQL = async (
  details: GcpConnectionDetails,
  dbUser: string,
  debug?: boolean
): Promise<void> => {
  // Ensure gcloud is authenticated
  await ensureGcloudAuth(debug);

  // Set the project
  await setGcloudProject(details.projectId, debug);

  // Always use Cloud SQL Proxy (works for both private and public IPs)
  print2("Connecting to CloudSQL database via Cloud SQL Proxy...");
  print2("");

  // Start Cloud SQL Proxy in the background and connect psql to it
  await connectToCloudSQLViaProxy(details, dbUser, debug);
};

const ensureGcloudAuth = async (debug?: boolean): Promise<void> => {
  try {
    // Check if gcloud is authenticated by trying to get an access token
    // This will fail if authentication is needed or tokens are expired
    const { command, args } = gcloudCommandArgs([
      "auth",
      "print-access-token",
    ]);
    await asyncSpawn({ debug: false }, command, args);
    // If we get here, authentication is working
    if (debug) {
      print2("gcloud is already authenticated.");
    }
  } catch (error) {
    // Not authenticated or tokens expired, need to login
    print2("gcloud authentication required. Please login...");
    try {
      const { command, args } = gcloudCommandArgs(["auth", "login"]);
      // Use interactive spawn for login (user needs to interact with browser)
      const child = spawnWithCleanEnv(command, args, {
        stdio: "inherit",
        env: createCleanChildEnv(),
      });

      await new Promise<void>((resolve, reject) => {
        child.on("exit", (code) => {
          if (code === 0) {
            resolve();
          } else {
            reject(new Error(`gcloud auth login exited with code ${code}`));
          }
        });

        child.on("error", (error) => {
          reject(error);
        });
      });

      print2("gcloud authentication successful.");
    } catch (loginError) {
      print2(`Error: gcloud authentication failed. ${loginError}`);
      print2("Please run 'gcloud auth login' manually and try again.");
      throw loginError;
    }
  }
};

const setGcloudProject = async (
  projectId: string,
  debug?: boolean
): Promise<void> => {
  try {
    // Check current project
    const { command: getCommand, args: getArgs } = gcloudCommandArgs([
      "config",
      "get-value",
      "project",
    ]);
    const currentProject = (await asyncSpawn({ debug: false }, getCommand, getArgs)).trim();

    if (currentProject === projectId) {
      if (debug) {
        print2(`gcloud project is already set to: ${projectId}`);
      }
      return;
    }

    // Set the project
    if (debug) {
      print2(`Setting gcloud project to: ${projectId}`);
    }
    const { command, args } = gcloudCommandArgs([
      "config",
      "set",
      "project",
      projectId,
    ]);
    await asyncSpawn({ debug }, command, args);
    if (debug) {
      print2(`gcloud project set to: ${projectId}`);
    }
  } catch (error) {
    print2(`Error: Failed to set gcloud project. ${error}`);
    throw error;
  }
};

const ensureCloudSqlProxy = async (debug?: boolean): Promise<string> => {
  try {
    // Get gcloud SDK root directory
    const { command: infoCommand, args: infoArgs } = gcloudCommandArgs([
      "info",
      "--format",
      "value(installation.sdk_root)",
    ]);
    const sdkRoot = (await asyncSpawn({ debug: false }, infoCommand, infoArgs)).trim();
    const proxyPath = `${sdkRoot}/bin/cloud_sql_proxy`;
    
    // Check if proxy binary exists
    if (fs.existsSync(proxyPath)) {
      if (debug) {
        print2("Cloud SQL Proxy binary found.");
      }
      // Ensure it's executable
      try {
        fs.chmodSync(proxyPath, 0o755);
      } catch {
        // Ignore chmod errors
      }
      return proxyPath;
    }

    // Not installed, need to install it
    print2("Cloud SQL Proxy component is required. Installing...");
    const { command: installCommand, args: installArgs } = gcloudCommandArgs([
      "components",
      "install",
      "cloud_sql_proxy",
      "--quiet",
    ]);
    await asyncSpawn({ debug }, installCommand, installArgs);
    
    // Verify installation
    if (!fs.existsSync(proxyPath)) {
      throw new Error("Cloud SQL Proxy installation completed but binary not found");
    }
    
    print2("Cloud SQL Proxy component installed successfully.");
    return proxyPath;
  } catch (error) {
    print2(`Error: Failed to check/install Cloud SQL Proxy component. ${error}`);
    print2("Please install it manually with: gcloud components install cloud_sql_proxy");
    throw error;
  }
};

const connectToCloudSQLViaProxy = async (
  details: GcpConnectionDetails,
  dbUser: string,
  debug?: boolean
): Promise<void> => {
  // Ensure application-default credentials are set up for the proxy
  try {
    const { command: adcCommand, args: adcArgs } = gcloudCommandArgs([
      "auth",
      "application-default",
      "print-access-token",
    ]);
    await asyncSpawn({ debug: false }, adcCommand, adcArgs);
    if (debug) {
      print2("Application-default credentials are available.");
    }
  } catch (error) {
    // Application-default credentials not set up, need to login
    print2("Setting up application-default credentials for Cloud SQL Proxy...");
    try {
      const { command: loginCommand, args: loginArgs } = gcloudCommandArgs([
        "auth",
        "application-default",
        "login",
      ]);
      const loginChild = spawnWithCleanEnv(loginCommand, loginArgs, {
        stdio: "inherit",
        env: createCleanChildEnv(),
      });

      await new Promise<void>((resolve, reject) => {
        loginChild.on("exit", (code) => {
          if (code === 0) {
            resolve();
          } else {
            reject(new Error(`gcloud auth application-default login exited with code ${code}`));
          }
        });

        loginChild.on("error", (error) => {
          reject(error);
        });
      });

      print2("Application-default credentials set up successfully.");
    } catch (loginError) {
      print2(`Error: Failed to set up application-default credentials. ${loginError}`);
      print2("Please run 'gcloud auth application-default login' manually and try again.");
      throw loginError;
    }
  }

  const proxyPath = await ensureCloudSqlProxy(debug);
  
  // Find an available local port
  const localPort = 5433; // Use a different port than default PostgreSQL to avoid conflicts
  
  // Start Cloud SQL Proxy in the background
  const instanceConnectionName = details.instanceConnectionName;
  const proxyArgs = [
    `-instances=${instanceConnectionName}=tcp:${localPort}`,
  ];

  if (debug) {
    print2(`Starting Cloud SQL Proxy: ${proxyPath} ${proxyArgs.join(" ")}`);
  }

  const proxyProcess = spawnWithCleanEnv(proxyPath, proxyArgs, {
    stdio: debug ? "inherit" : "pipe",
    env: createCleanChildEnv(),
  });

  // Wait a bit for the proxy to start
  await new Promise<void>((resolve) => {
    const timeout = setTimeout(() => {
      resolve();
    }, 2000);

    // Check if proxy started successfully by looking for "Ready for new connections" or error
    let output = "";
    if (proxyProcess.stdout) {
      proxyProcess.stdout.on("data", (data: Buffer) => {
        output += data.toString();
        if (output.includes("Ready for new connections") || output.includes("ready")) {
          clearTimeout(timeout);
          resolve();
        }
      });
    }
    if (proxyProcess.stderr) {
      proxyProcess.stderr.on("data", (data: Buffer) => {
        output += data.toString();
        if (output.includes("Ready for new connections") || output.includes("ready")) {
          clearTimeout(timeout);
          resolve();
        }
      });
    }

    proxyProcess.on("error", (error: Error) => {
      clearTimeout(timeout);
      print2(`Error: Failed to start Cloud SQL Proxy. ${error.message}`);
      sys.exit(1);
    });
  });

  // Generate a login token for CloudSQL IAM authentication
  const { command: tokenCommand, args: tokenArgs } = gcloudCommandArgs([
    "sql",
    "generate-login-token",
    "--project",
    details.projectId,
  ]);

  let password: string;
  try {
    password = (await asyncSpawn({ debug: false }, tokenCommand, tokenArgs)).trim();
    if (debug) {
      print2("Generated CloudSQL login token.");
    }
  } catch (error) {
    if (debug) {
      print2(`Token generation failed: ${error}`);
    }
    password = "";
  }

  // Connect psql to localhost:localPort
  const connectionString = `host=localhost port=${localPort} dbname=${details.database} user=${dbUser} sslmode=disable`;

  const env = { ...process.env };
  if (password) {
    env.PGPASSWORD = password;
  }

  if (debug) {
    print2(`Connecting psql to localhost:${localPort}/${details.database} as ${dbUser}`);
  }

  try {
    const psqlProcess = spawnWithCleanEnv("psql", [connectionString], {
      stdio: "inherit",
      env: createCleanChildEnv(env),
    });

    psqlProcess.on("error", (error: Error) => {
      print2(`Error: Failed to launch psql. ${error.message}`);
      print2("Make sure psql is installed and in your PATH.");
      proxyProcess.kill();
      sys.exit(1);
    });

    // Wait for psql to exit
    await new Promise<void>((resolve) => {
      psqlProcess.on("exit", () => {
        resolve();
      });
    });
  } finally {
    // Clean up: kill the proxy process
    if (proxyProcess && !proxyProcess.killed) {
      if (debug) {
        print2("Stopping Cloud SQL Proxy...");
      }
      proxyProcess.kill();
    }
  }
};

