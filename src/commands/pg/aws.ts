/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { asyncSpawn } from "../../common/subprocess";
import { fetchCommand, fetchIntegrationConfig } from "../../drivers/api";
import { print2 } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import { PsqlCommandArgs } from "../../types/psql";
import { createCleanChildEnv, spawnWithCleanEnv } from "../../util";
import { AwsConnectionDetails } from "./types";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { sys } from "typescript";
import yargs from "yargs";

/**
 * Extracts AWS RDS connection details from the permission request
 *
 * Extracts RDS endpoint, SSO configuration, and other AWS-specific details.
 * Attempts to query the backend or AWS for the RDS endpoint if not provided
 * in the response. Constructs SSO Start URL from IDC ID if not provided.
 */
export const extractAwsConnectionDetails = async (
  perm: Record<string, unknown>,
  resource: Record<string, unknown>,
  region: string,
  databaseName: string,
  instanceName: string,
  accountId: string,
  idcId: string,
  idcRegion: string,
  port: number,
  roleName: string,
  generated: unknown,
  debug?: boolean,
  authn?: Authn,
  args?: yargs.ArgumentsCamelCase<PsqlCommandArgs>
): Promise<AwsConnectionDetails | null> => {
  if (!region || !databaseName || !accountId || !idcId || !idcRegion) {
    print2(
      "Error: Missing required AWS RDS connection details in request response:"
    );
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
  let ssoStartUrl =
    (resource.ssoStartUrl as string) ||
    (resource.sso_start_url as string) ||
    (resource.ssoStartURL as string) ||
    (perm.ssoStartUrl as string);

  if (!ssoStartUrl) {
    // Construct SSO Start URL from IDC ID
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
  let rdsHost =
    (resource.rdsHost as string) ||
    (resource.hostname as string) ||
    (resource.endpoint as string) ||
    (resource.host as string) ||
    (resource.address as string) ||
    (resource.dbEndpoint as string) ||
    (resource.dbHost as string) ||
    (perm.rdsHost as string) ||
    (perm.endpoint as string) ||
    (perm.hostname as string) ||
    (perm.host as string) ||
    ((generated as Record<string, unknown>)?.rdsHost as string) ||
    ((generated as Record<string, unknown>)?.endpoint as string);

  // If backend doesn't provide it, we'll need to query AWS or construct it
  if (!rdsHost) {
    // Extract DB instance identifier from ARN or instance name
    let dbInstanceIdentifier: string | null = null;

    // Try to extract from ARN first
    const arn = resource.arn as string;
    if (arn && typeof arn === "string" && arn.includes(":dbuser:")) {
      const arnParts = arn.split(":dbuser:");
      if (arnParts.length === 2 && arnParts[1]) {
        const dbUserPart = arnParts[1];
        const dbInstancePart = dbUserPart.split("/")[0];
        if (dbInstancePart) {
          dbInstanceIdentifier = dbInstancePart;
          if (debug) {
            print2(
              `Extracted DB instance identifier from ARN: ${dbInstanceIdentifier}`
            );
          }
        }
      }
    }

    // Fallback to instance name if ARN extraction failed
    if (!dbInstanceIdentifier) {
      const instance = (perm.instance as string) || instanceName;
      dbInstanceIdentifier = instanceName;

      // Parse instance identifier from full instance path if needed
      if (instance && typeof instance === "string") {
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
        print2(
          `Using instance name as DB instance identifier: ${dbInstanceIdentifier}`
        );
      }
    }

    if (!dbInstanceIdentifier) {
      print2("Error: Could not determine RDS instance identifier");
      return null;
    }

    // Try to query backend for instance details to get the endpoint
    if (authn && args) {
      const fullInstancePath = (perm.instance as string) || instanceName;
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
        // Fallback: construct endpoint from instance identifier
        const endpoint = await getRdsEndpoint(
          dbInstanceIdentifier,
          region,
          undefined,
          debug
        );
        rdsHost =
          endpoint ?? `${dbInstanceIdentifier}.${region}.rds.amazonaws.com`;
      }
    } else {
      // Fallback: construct endpoint from instance identifier
      const endpoint = await getRdsEndpoint(
        dbInstanceIdentifier,
        region,
        undefined,
        debug
      );
      rdsHost =
        endpoint ?? `${dbInstanceIdentifier}.${region}.rds.amazonaws.com`;
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
  const gen = generated as Record<string, unknown>;
  const permissionSetName =
    ((gen?.resource as Record<string, unknown>)?.name as string) ||
    (gen?.permissionSet as string) ||
    roleName;

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
    roleName: permissionSetName,
  };
};

/**
 * Queries the backend API to retrieve the RDS endpoint for an instance
 */
export const queryBackendForEndpoint = async (
  instanceName: string,
  _region: string,
  authn: Authn,
  args: yargs.ArgumentsCamelCase<PsqlCommandArgs>,
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
    let response: Record<string, unknown> | null = null;

    // Approach 1: Try querying integration config for pg/rds
    try {
      if (debug) {
        print2("Trying to fetch integration config for pg/rds...");
      }
      for (const integrationName of ["pg", "rds"]) {
        try {
          const config = await fetchIntegrationConfig<Record<string, unknown>>(
            authn,
            integrationName,
            debug
          );
          if (config && typeof config === "object" && config.config) {
            const integrationConfig = config.config as Record<string, unknown>;

            // Search for endpoint in access-management
            if (
              integrationConfig["access-management"] &&
              typeof integrationConfig["access-management"] === "object"
            ) {
              const accessManagement = integrationConfig[
                "access-management"
              ] as Record<string, unknown>;

              // Try to find instance by name
              for (const [key, value] of Object.entries(accessManagement)) {
                if (
                  value &&
                  typeof value === "object" &&
                  (value as Record<string, unknown>).installType
                ) {
                  const installType = (value as Record<string, unknown>)
                    .installType as Record<string, unknown>;
                  const hostname = installType?.hostname as string;
                  if (hostname && typeof hostname === "string") {
                    if (
                      key.includes(instanceName) ||
                      instanceName.includes(key) ||
                      (fullInstancePath &&
                        (key.includes(instanceName) ||
                          fullInstancePath.includes(key)))
                    ) {
                      if (debug) {
                        print2(
                          `Found endpoint in integration config for instance '${key}': ${hostname}`
                        );
                      }
                      return hostname;
                    }
                  }
                }
              }

              // Search for any hostname that looks like RDS endpoint
              const searchForEndpoint = (
                obj: Record<string, unknown>
              ): string | null => {
                if (!obj || typeof obj !== "object") return null;
                for (const [, value] of Object.entries(obj)) {
                  if (
                    typeof value === "string" &&
                    value.includes(".rds.amazonaws.com")
                  ) {
                    const endpointParts = value.split(".");
                    const endpointInstanceName = endpointParts[0] || "";
                    if (
                      value.includes(instanceName) ||
                      instanceName.includes(endpointInstanceName)
                    ) {
                      if (debug) {
                        print2(`Found matching RDS endpoint: ${value}`);
                      }
                      return value;
                    }
                  }
                  if (typeof value === "object" && value !== null) {
                    const found = searchForEndpoint(
                      value as Record<string, unknown>
                    );
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
          }
        } catch (error) {
          if (debug) {
            print2(
              `Failed to fetch integration config for ${integrationName}: ${String(error)}`
            );
          }
        }
      }
    } catch (error) {
      if (debug) {
        print2(`Integration config query failed: ${String(error)}`);
      }
    }

    // Approach 2: Query using the full instance path via command
    if (fullInstancePath) {
      try {
        if (debug) {
          print2(`Trying query with full instance path: ${fullInstancePath}`);
        }
        response = await fetchCommand<Record<string, unknown>>(authn, args, [
          "ls",
          "pg",
          "role",
          "instance",
          fullInstancePath,
          "--json",
        ]);
        if (
          response &&
          response.items &&
          (response.items as unknown[]).length > 0
        ) {
          if (debug) {
            print2("Got response with full instance path query");
          }
        }
      } catch (error) {
        if (debug) {
          print2(`Query with full path failed: ${String(error)}`);
        }
      }
    }

    // Approach 3: Query using just the instance name
    if (!response || !response.items || !(response.items as unknown[]).length) {
      try {
        if (debug) {
          print2(`Trying query with instance name: ${instanceName}`);
        }
        response = await fetchCommand<Record<string, unknown>>(authn, args, [
          "ls",
          "pg",
          "role",
          "instance",
          instanceName,
          "--json",
        ]);
      } catch (error) {
        if (debug) {
          print2(`Query with instance name failed: ${String(error)}`);
        }
      }
    }

    if (response && response.items && Array.isArray(response.items)) {
      // Look for endpoint in the response items
      for (const item of response.items as Record<string, unknown>[]) {
        if (item.value && typeof item.value === "string") {
          if (item.value.includes(".rds.amazonaws.com")) {
            if (debug) {
              print2(`Found RDS endpoint in backend response: ${item.value}`);
            }
            return item.value;
          }
        }
        if (
          item.key &&
          typeof item.key === "string" &&
          item.key.includes(".rds.amazonaws.com")
        ) {
          if (debug) {
            print2(`Found RDS endpoint in backend response (key): ${item.key}`);
          }
          return item.key;
        }
      }
    }

    if (debug) {
      print2("Backend response structure:");
      print2(JSON.stringify(response, null, 2));
    }
  } catch (error) {
    if (debug) {
      print2(`Failed to query backend for endpoint: ${String(error)}`);
    }
  }

  return null;
};

/**
 * Retrieves the RDS endpoint for a database instance
 */
export const getRdsEndpoint = async (
  dbInstanceIdentifier: string,
  region: string,
  profileName?: string,
  debug?: boolean
): Promise<string | null> => {
  // If we have a profile (credentials), query AWS RDS for the actual endpoint
  if (profileName) {
    try {
      if (debug) {
        print2(
          `Querying AWS RDS for endpoint of instance: ${dbInstanceIdentifier}`
        );
      }

      try {
        const result = await asyncSpawn({ debug }, "aws", [
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
        ]);

        const endpoint = result.trim();
        if (endpoint && endpoint !== "None" && !endpoint.includes("error")) {
          if (debug) {
            print2(`Retrieved RDS endpoint from AWS: ${endpoint}`);
          }
          return endpoint;
        }
      } catch {
        if (debug) {
          print2(`Query by identifier failed, trying to list instances...`);
        }
      }
    } catch (error) {
      if (debug) {
        print2(`Failed to query AWS RDS for endpoint: ${String(error)}`);
        print2("Falling back to constructed endpoint");
      }
    }
  }

  // Fallback: construct endpoint from instance identifier
  const constructedEndpoint = `${dbInstanceIdentifier}.${region}.rds.amazonaws.com`;

  if (debug) {
    print2(`Using constructed RDS endpoint: ${constructedEndpoint}`);
    print2(`(Instance identifier: ${dbInstanceIdentifier})`);
    print2(
      `Note: If connection fails, the endpoint may need to be provided by the backend.`
    );
  }

  return constructedEndpoint;
};

/**
 * Parses an AWS config file and returns a map of section names to their key-value pairs
 */
const parseAwsConfig = (
  configPath: string
): Map<string, Map<string, string>> => {
  const sections = new Map<string, Map<string, string>>();

  if (!fs.existsSync(configPath)) {
    return sections;
  }

  const content = fs.readFileSync(configPath, "utf-8");
  const lines = content.split("\n");
  let currentSection: string | null = null;

  for (const line of lines) {
    const trimmedLine = line.trim();

    // Skip empty lines and comments
    if (
      !trimmedLine ||
      trimmedLine.startsWith("#") ||
      trimmedLine.startsWith(";")
    ) {
      continue;
    }

    // Check for section header [section-name] or [profile name]
    const sectionMatch = trimmedLine.match(/^\[(.+)\]$/);
    if (sectionMatch && sectionMatch[1]) {
      currentSection = sectionMatch[1];
      if (!sections.has(currentSection)) {
        sections.set(currentSection, new Map());
      }
      continue;
    }

    // Parse key = value
    if (currentSection) {
      const kvMatch = trimmedLine.match(/^([^=]+)=(.*)$/);
      if (kvMatch && kvMatch[1] && kvMatch[2] !== undefined) {
        const key = kvMatch[1].trim();
        const value = kvMatch[2].trim();
        sections.get(currentSection)!.set(key, value);
      }
    }
  }

  return sections;
};

/**
 * Finds an existing AWS SSO profile that matches the given connection details
 * Returns the profile name if found, null otherwise
 */
const findExistingSsoProfile = (
  details: AwsConnectionDetails,
  debug?: boolean
): string | null => {
  const awsConfigPath = path.join(os.homedir(), ".aws", "config");
  const sections = parseAwsConfig(awsConfigPath);

  if (debug) {
    print2(`Searching for existing SSO profile matching:`);
    print2(`  sso_start_url: ${details.ssoStartUrl}`);
    print2(`  sso_region: ${details.ssoRegion}`);
    print2(`  sso_account_id: ${details.ssoAccountId}`);
    print2(`  sso_role_name: ${details.roleName}`);
    print2(`  region: ${details.region}`);
  }

  // Look for p0-pg-* profiles that match our configuration
  for (const [sectionName, sectionData] of sections) {
    // Only check profile sections that start with "profile p0-pg-"
    if (!sectionName.startsWith("profile p0-pg-")) {
      continue;
    }

    const profileName = sectionName.replace("profile ", "");

    // Check profile-level attributes
    const ssoAccountId = sectionData.get("sso_account_id");
    const ssoRoleName = sectionData.get("sso_role_name");
    const region = sectionData.get("region");
    const ssoSessionName = sectionData.get("sso_session");

    if (ssoAccountId !== details.ssoAccountId) continue;
    if (ssoRoleName !== details.roleName) continue;
    if (region !== details.region) continue;

    // If this profile uses sso_session, check the session block
    if (ssoSessionName) {
      const sessionSection = sections.get(`sso-session ${ssoSessionName}`);
      if (!sessionSection) continue;

      const sessionStartUrl = sessionSection.get("sso_start_url");
      const sessionRegion = sessionSection.get("sso_region");

      if (sessionStartUrl !== details.ssoStartUrl) continue;
      if (sessionRegion !== details.ssoRegion) continue;
    } else {
      // Legacy profile format (inline sso_* fields)
      const ssoStartUrl = sectionData.get("sso_start_url");
      const ssoRegion = sectionData.get("sso_region");

      if (ssoStartUrl !== details.ssoStartUrl) continue;
      if (ssoRegion !== details.ssoRegion) continue;
    }

    // Found a matching profile!
    if (debug) {
      print2(`Found existing matching SSO profile: ${profileName}`);
    }
    return profileName;
  }

  if (debug) {
    print2("No existing matching SSO profile found");
  }
  return null;
};

/**
 * Configures an AWS SSO profile in the AWS config file
 * Reuses an existing profile if one matches the connection details
 */
export const configureAwsSsoProfile = async (
  details: AwsConnectionDetails,
  debug?: boolean
): Promise<string> => {
  try {
    const awsConfigDir = path.join(os.homedir(), ".aws");
    const awsConfigPath = path.join(awsConfigDir, "config");

    // Ensure .aws directory exists
    if (!fs.existsSync(awsConfigDir)) {
      fs.mkdirSync(awsConfigDir, { recursive: true });
    }

    // Check for existing matching profile first
    const existingProfile = findExistingSsoProfile(details, debug);
    if (existingProfile) {
      if (debug) {
        print2(`Reusing existing SSO profile: ${existingProfile}`);
      }
      return existingProfile;
    }

    // Create unique profile name (only if no existing match)
    const timestamp = Date.now();
    const profileName = `p0-pg-${timestamp}`;
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
    try {
      fs.appendFileSync(awsConfigPath, configContent);
    } catch (error) {
      throw new Error(
        `Failed to write AWS config file: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    if (debug) {
      print2(`Configured new AWS SSO profile: ${profileName}`);
      print2(`Appended to ${awsConfigPath}`);
    }

    return profileName;
  } catch (error) {
    throw new Error(
      `Failed to configure AWS SSO profile: ${error instanceof Error ? error.message : String(error)}`
    );
  }
};

/**
 * Logs in to AWS SSO using the specified profile
 */
export const loginAwsSso = async (
  profileName: string,
  debug?: boolean
): Promise<void> => {
  print2(`Logging in to AWS SSO with profile ${profileName}...`);

  await asyncSpawn({ debug }, "aws", [
    "sso",
    "login",
    "--profile",
    profileName,
  ]);
  print2("AWS SSO login successful.");
};

/**
 * Generates an IAM database authentication token for RDS
 */
export const generateDbAuthToken = async (
  details: AwsConnectionDetails,
  dbUser: string,
  profileName: string,
  debug?: boolean
): Promise<string> => {
  if (debug) {
    print2(`Generating IAM auth token for user '${dbUser}'...`);
  }

  const token = await asyncSpawn({ debug }, "aws", [
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
  ]);

  const trimmedToken = token.trim();
  if (!trimmedToken) {
    throw new Error("Failed to generate DB auth token: empty response");
  }

  if (debug) {
    print2("Token generated successfully.");
  }

  return trimmedToken;
};

/**
 * Generates an IAM database authentication token with automatic SSO login on failure.
 *
 * This function attempts to generate a token first. If it fails due to expired or
 * missing credentials, it will automatically trigger SSO login and retry once.
 */
export const generateDbAuthTokenWithAutoLogin = async (
  details: AwsConnectionDetails,
  dbUser: string,
  profileName: string,
  debug?: boolean
): Promise<string> => {
  // First, try to generate token with existing credentials
  try {
    if (debug) {
      print2("Attempting to use existing AWS credentials...");
    }
    const token = await generateDbAuthToken(
      details,
      dbUser,
      profileName,
      debug
    );
    if (debug) {
      print2("Successfully used existing credentials.");
    }
    return token;
  } catch (firstError) {
    // Check if this looks like an auth/credentials error
    const errorMessage =
      firstError instanceof Error ? firstError.message : String(firstError);
    const isAuthError =
      errorMessage.includes("expired") ||
      errorMessage.includes("credentials") ||
      errorMessage.includes("token") ||
      errorMessage.includes("SSO") ||
      errorMessage.includes("UnauthorizedException") ||
      errorMessage.includes("AccessDenied") ||
      errorMessage.includes("not authorized") ||
      errorMessage.includes("Unable to locate credentials");

    if (!isAuthError) {
      // Not an auth error - might be a permission or config issue, don't retry
      if (debug) {
        print2(`Token generation failed with non-auth error: ${errorMessage}`);
      }
      throw firstError;
    }

    // Auth error - try logging in and retrying
    if (debug) {
      print2(`Credentials appear expired or invalid. Initiating SSO login...`);
    } else {
      print2("AWS credentials expired or not found. Logging in...");
    }

    try {
      await loginAwsSso(profileName, debug);
    } catch (loginError) {
      print2("Error: Failed to login to AWS SSO.");
      if (debug && loginError instanceof Error) {
        print2(`Details: ${loginError.message}`);
      }
      throw loginError;
    }

    // Retry token generation after login
    print2("Retrying token generation after login...");
    try {
      const token = await generateDbAuthToken(
        details,
        dbUser,
        profileName,
        debug
      );
      return token;
    } catch (retryError) {
      print2(
        "Error: Failed to generate database authentication token after login."
      );
      if (debug && retryError instanceof Error) {
        print2(`Details: ${retryError.message}`);
      }
      throw retryError;
    }
  }
};

/**
 * Connects to the RDS database using psql with IAM authentication
 */
export const connectToDatabase = async (
  details: AwsConnectionDetails,
  dbUser: string,
  token: string,
  ssl?: boolean,
  debug?: boolean
): Promise<void> => {
  print2("Connecting to database...");
  print2("");

  const sslMode = ssl ? "require" : "prefer";
  const connectionString = `host=${details.rdsHost} port=${details.port} dbname=${details.database} user=${dbUser} sslmode=${sslMode}`;

  // Set PGPASSWORD environment variable
  const env = { ...process.env, PGPASSWORD: token };

  try {
    // Use spawn to connect to psql interactively
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
    print2(`Error: Failed to connect to database. ${String(error)}`);
    throw error;
  }
};

/**
 * Prints AWS RDS connection details
 */
export const printAwsConnectionDetails = async (
  details: AwsConnectionDetails,
  dbUser: string,
  token: string,
  ssl?: boolean,
  _debug?: boolean
): Promise<void> => {
  // Construct postgresql:// URL with IAM token
  const sslMode = ssl ? "require" : "prefer";
  const connectionUrl = `postgresql://${encodeURIComponent(dbUser)}:${encodeURIComponent(token)}@${details.rdsHost}:${details.port}/${encodeURIComponent(details.database)}?sslmode=${sslMode}`;

  print2("");
  print2("═══════════════════════════════════════════════════════════════");
  print2("  POSTGRES CONNECTION DETAILS");
  print2("═══════════════════════════════════════════════════════════════");
  print2(`  Host:     ${details.rdsHost}`);
  print2(`  Port:     ${details.port}`);
  print2(`  Database: ${details.database}`);
  print2(`  Username: ${dbUser}`);
  print2(`  Password: ${token}`);
  print2(`  SSL Mode: ${sslMode}`);
  print2("");
  print2("Connection URL:");
  print2(`  ${connectionUrl}`);
  print2("═══════════════════════════════════════════════════════════════");
  print2("");

  print2("Use these details with psql or any PostgreSQL client.");
};
