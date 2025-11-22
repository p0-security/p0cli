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
import { fetchCommand, fetchIntegrationConfig } from "../drivers/api";
import { getTenantConfig } from "../drivers/config";
import { defaultConfig } from "../drivers/env";

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
  // Validate required CLI tools are installed
  await validateCliTools(args.debug);

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

  // Force exit to prevent hanging
  if (process.env.NODE_ENV !== "unit") {
    process.exit(0);
  }
};

const validateCliTools = async (debug?: boolean) => {
  const tools = [
    { name: "aws", description: "AWS CLI" },
    { name: "psql", description: "PostgreSQL client" },
  ];

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

  try {
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
      return null;
    }

    return {
      request: response.request,
    };
  } catch (error: any) {
    // Handle timeout or network errors - check if request was already approved
    const isTimeoutError = error instanceof Error && error.name === "TimeoutError";
    const isNetworkError = typeof error === "string" && error.startsWith("Network error:");
    
    if (isTimeoutError || isNetworkError) {
      if (isTimeoutError) {
        print2("Your request did not complete within 5 minutes.");
      } else {
        print2("Network error occurred while waiting for request to complete.");
      }
      // Check if we can use existing approval
      print2("Attempting to use existing approval if available...");
      try {
        const response = await request("request")<PermissionRequest<PsqlPermissionSpec>>(
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
            wait: false,
            debug: args.debug,
          },
          authn,
          { message: "quiet" }
        );
        if (response && (response.isPreexisting || response.request)) {
          print2("Using existing approval.");
          const result = await decodeProvisionStatus<PsqlPermissionSpec>(response.request);
          if (result) {
            return { request: response.request };
          }
        }
      } catch (retryError) {
        // Ignore retry errors - we'll throw the original error
        if (args.debug) {
          print2(`Retry check failed: ${retryError}`);
        }
      }
    }
    throw error;
  }
};

type ConnectionDetails = {
  rdsHost: string;
  region: string;
  port: number;
  database: string;
  ssoStartUrl: string;
  ssoRegion: string;
  ssoAccountId: string;
  roleName: string;
};

const extractConnectionDetails = async (
  request: PermissionRequest<PsqlPermissionSpec>,
  roleName: string,
  debug?: boolean,
  authn?: any,
  args?: any
): Promise<ConnectionDetails | null> => {
  try {
    const { permission, generated } = request;
    const resource = permission.resource as any;

    // Extract from permission and resource (actual backend response structure)
    // The permission object has: region, databaseName, instanceName, instance, parent, resource
    const perm = permission as any;
    const region = perm.region || resource.region;
    const databaseName = perm.databaseName || resource.databaseName;
    const instanceName = perm.instanceName || resource.instanceName;
    const accountId = resource.accountId || resource.account || perm.parent;
    const idcId = resource.idcId;
    const idcRegion = resource.idcRegion || resource.idc_region || region;

    // Extract permission set name from generated resource
    // The permission set name is in generated.resource.name
    const gen = generated as any;
    const permissionSetName = gen?.resource?.name || gen?.permissionSet || roleName;
    
    if (debug) {
      print2(`Using permission set name: ${permissionSetName}`);
    }

    // Default port for PostgreSQL
    const port = resource.port || 5432;

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

    if (!region || !databaseName || !accountId || !idcId || !idcRegion) {
      print2("Error: Missing required connection details in request response:");
      print2(`  Region: ${region || "missing"}`);
      print2(`  Database: ${databaseName || "missing"}`);
      print2(`  Account ID: ${accountId || "missing"}`);
      print2(`  IDC ID: ${idcId || "missing"}`);
      print2(`  IDC Region: ${idcRegion || "missing"}`);
      if (debug) {
        print2("Full permission object:");
        print2(JSON.stringify(permission, null, 2));
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
      // Check in generated object
      (gen as any)?.rdsHost ||
      (gen as any)?.endpoint ||
      (gen as any)?.hostname ||
      (gen as any)?.connectionString ||
      (gen as any)?.connection?.host ||
      (gen as any)?.connection?.endpoint ||
      (gen as any)?.connection?.hostname ||
      // Check in full request object (maybe it's at the top level)
      (request as any)?.rdsHost ||
      (request as any)?.endpoint ||
      (request as any)?.hostname ||
      (request as any)?.connectionString;
    
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

    return {
      rdsHost: rdsHost.trim(),
      region: String(region),
      port: portNum,
      database: String(databaseName),
      ssoStartUrl,
      ssoRegion: String(idcRegion),
      ssoAccountId: String(accountId),
      roleName: permissionSetName, // Use permission set name from response, not user-provided role
    };
  } catch (error) {
    print2(`Error extracting connection details: ${error}`);
    if (debug) {
      print2(`Stack: ${error instanceof Error ? error.stack : String(error)}`);
    }
    return null;
  }
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
  details: ConnectionDetails,
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
  details: ConnectionDetails,
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
  details: ConnectionDetails,
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

