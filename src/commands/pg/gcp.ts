/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { asyncSpawn } from "../../common/subprocess";
import { print2 } from "../../drivers/stdio";
import { ensureGcloudAuth, setGcloudProject } from "../../plugins/google/auth";
import { gcloudCommandArgs } from "../../plugins/google/util";
import {
  createCleanChildEnv,
  getOperatingSystem,
  spawnWithCleanEnv,
} from "../../util";
import { GcpConnectionDetails } from "./types";
import * as fs from "node:fs";
import * as path from "node:path";
import { sys } from "typescript";

/**
 * Extracts GCP CloudSQL connection details from the permission request
 *
 * Constructs the instance connection name in the format project:region:instance
 * and validates that all required fields are present.
 */
export const extractGcpConnectionDetails = async (
  perm: Record<string, unknown>,
  resource: Record<string, unknown>,
  region: string,
  databaseName: string,
  instanceName: string,
  port: number,
  debug?: boolean
): Promise<GcpConnectionDetails | null> => {
  // Extract GCP-specific fields
  const projectId =
    (perm.parent as string) ||
    (resource?.projectId as string) ||
    (perm.projectId as string);

  if (!region || !databaseName || !projectId || !instanceName) {
    print2("Error: Missing required GCP CloudSQL connection details:");
    print2(`  Region: ${region || "missing"}`);
    print2(`  Database: ${databaseName || "missing"}`);
    print2(`  Project ID: ${projectId || "missing"}`);
    print2(`  Instance Name: ${instanceName || "missing"}`);
    return null;
  }

  // Get instance connection name - format: project-id:region:instance-name
  let instanceConnectionName =
    (perm.instanceConnectionName as string) ||
    (perm.connectionName as string) ||
    (perm.connection_name as string) ||
    (resource?.instanceConnectionName as string) ||
    (resource?.connectionName as string) ||
    (resource?.connection_name as string);

  if (!instanceConnectionName) {
    // Construct from project:region:instance
    instanceConnectionName = `${projectId}:${region}:${instanceName}`;
    if (debug) {
      print2(`Constructed instance connection name: ${instanceConnectionName}`);
    }
  } else {
    if (debug) {
      print2(
        `Using instance connection name from backend: ${instanceConnectionName}`
      );
    }
  }

  // Ensure port is a number
  const portNum = typeof port === "number" ? port : parseInt(String(port), 10);
  if (isNaN(portNum) || portNum <= 0) {
    print2(`Error: Invalid port number: ${port}`);
    return null;
  }

  // Try to get public IP if available
  const publicIp =
    (perm.publicIp as string) ||
    (resource?.publicIp as string) ||
    (perm.ipAddress as string) ||
    (resource?.ipAddress as string) ||
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

/**
 * Checks if required GCP APIs are enabled for CloudSQL connections
 *
 * Verifies that the Cloud SQL Admin API and IAP (Identity-Aware Proxy) API
 * are enabled for the project. If not, warns the user with instructions
 * on how to enable them.
 *
 * @param projectId - The GCP project ID to check
 * @param debug - Whether to print debug information
 * @returns Object with flags indicating which APIs are enabled
 */
export const checkGcpApisEnabled = async (
  projectId: string,
  debug?: boolean
): Promise<{ cloudSqlEnabled: boolean; iapEnabled: boolean }> => {
  const result = { cloudSqlEnabled: false, iapEnabled: false };

  try {
    // List enabled services for the project
    const { command, args } = gcloudCommandArgs([
      "services",
      "list",
      "--enabled",
      "--project",
      projectId,
      "--format",
      "value(config.name)",
    ]);

    const output = await asyncSpawn({ debug: false }, command, args);
    const enabledServices = output.trim().split("\n");

    // Check for Cloud SQL Admin API
    result.cloudSqlEnabled = enabledServices.some(
      (s) =>
        s.includes("sqladmin.googleapis.com") ||
        s.includes("sql-component.googleapis.com")
    );

    // Check for IAP API
    result.iapEnabled = enabledServices.some((s) =>
      s.includes("iap.googleapis.com")
    );

    if (debug) {
      print2(`Cloud SQL Admin API enabled: ${result.cloudSqlEnabled}`);
      print2(`IAP API enabled: ${result.iapEnabled}`);
    }

    // Warn user about missing APIs
    if (!result.cloudSqlEnabled) {
      print2("");
      print2("WARNING: Cloud SQL Admin API is not enabled for this project.");
      print2("   This API is required for Cloud SQL Proxy connections.");
      print2("");
      print2("   To enable it, run:");
      print2(
        `   gcloud services enable sqladmin.googleapis.com --project ${projectId}`
      );
      print2("");
    }

    if (!result.iapEnabled) {
      print2("");
      print2(
        "WARNING: Identity-Aware Proxy (IAP) API is not enabled for this project."
      );
      print2("   This API may be required for private CloudSQL instances.");
      print2("");
      print2("   To enable it, run:");
      print2(
        `   gcloud services enable iap.googleapis.com --project ${projectId}`
      );
      print2("");
    }
  } catch (error) {
    if (debug) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      print2(`Warning: Could not check enabled APIs: ${errorMessage}`);
    }
    // If we can't check, assume they might be enabled and continue
    // The actual connection will fail with a clearer error if they're not
  }

  return result;
};

/**
 * Connects to a GCP CloudSQL database
 *
 * Ensures gcloud authentication and project configuration, then initiates
 * the Cloud SQL Proxy connection flow.
 */
export const connectToCloudSQL = async (
  details: GcpConnectionDetails,
  dbUser: string,
  ssl?: boolean,
  debug?: boolean
): Promise<void> => {
  // Ensure gcloud is authenticated
  await ensureGcloudAuth(debug);

  // Set the project
  await setGcloudProject(details.projectId, debug);

  // Check if required APIs are enabled (warn user if not)
  await checkGcpApisEnabled(details.projectId, debug);

  // Always use Cloud SQL Proxy (works for both private and public IPs)
  print2("Connecting to CloudSQL database via Cloud SQL Proxy...");
  print2("");

  // Start Cloud SQL Proxy in the background and connect psql to it
  await connectToCloudSQLViaProxy(details, dbUser, ssl, debug);
};

/**
 * Ensures the Cloud SQL Proxy component is installed and available
 */
export const ensureCloudSqlProxy = async (debug?: boolean): Promise<string> => {
  try {
    // Get gcloud SDK root directory
    const { command: infoCommand, args: infoArgs } = gcloudCommandArgs([
      "info",
      "--format",
      "value(installation.sdk_root)",
    ]);
    let sdkRoot = (
      await asyncSpawn({ debug: false }, infoCommand, infoArgs)
    ).trim();

    // Normalize the path
    sdkRoot = path.normalize(sdkRoot);

    if (debug) {
      print2(`gcloud SDK root: ${sdkRoot}`);
    }

    // On Windows, the binary is cloud_sql_proxy.exe, on Unix it's cloud_sql_proxy
    const binaryName =
      process.platform === "win32" ? "cloud_sql_proxy.exe" : "cloud_sql_proxy";
    const binDir = path.join(sdkRoot, "bin");
    const proxyPath = path.join(binDir, binaryName);

    if (debug) {
      print2(`Checking for Cloud SQL Proxy at: ${proxyPath}`);
    }

    // Check if proxy binary exists
    if (fs.existsSync(proxyPath)) {
      if (debug) {
        print2("Cloud SQL Proxy binary found.");
      }
      // Ensure it's executable (only on Unix)
      if (process.platform !== "win32") {
        try {
          fs.chmodSync(proxyPath, 0o755);
        } catch {
          // Ignore chmod errors
        }
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
    const pathsToCheck = [
      proxyPath,
      path.join(binDir, "cloud_sql_proxy.exe"),
      path.join(binDir, "cloud_sql_proxy"),
    ];

    const uniquePaths = [...new Set(pathsToCheck)];

    for (const checkPath of uniquePaths) {
      if (fs.existsSync(checkPath)) {
        if (debug) {
          print2(`Found Cloud SQL Proxy at: ${checkPath}`);
        }
        print2("Cloud SQL Proxy component installed successfully.");
        return checkPath;
      }
    }

    throw new Error(
      `Cloud SQL Proxy installation completed but binary not found at any of: ${uniquePaths.join(", ")}`
    );
  } catch (error) {
    print2(
      `Error: Failed to check/install Cloud SQL Proxy component. ${String(error)}`
    );
    print2(
      "Please install it manually with: gcloud components install cloud_sql_proxy"
    );
    throw error;
  }
};

/**
 * Connects to CloudSQL via Cloud SQL Proxy
 */
export const connectToCloudSQLViaProxy = async (
  details: GcpConnectionDetails,
  dbUser: string,
  ssl?: boolean,
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
  } catch {
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
            reject(
              new Error(
                `gcloud auth application-default login exited with code ${code}`
              )
            );
          }
        });

        loginChild.on("error", (error) => {
          reject(error);
        });
      });

      print2("Application-default credentials set up successfully.");
    } catch (loginError) {
      print2(
        `Error: Failed to set up application-default credentials. ${String(loginError)}`
      );
      print2(
        "Please run 'gcloud auth application-default login' manually and try again."
      );
      throw loginError;
    }
  }

  const proxyPath = await ensureCloudSqlProxy(debug);

  // Find an available local port
  const localPort = 5433;

  // Start Cloud SQL Proxy in the background
  const instanceConnectionName = details.instanceConnectionName;
  const proxyArgs = [`-instances=${instanceConnectionName}=tcp:${localPort}`];

  if (debug) {
    print2(`Starting Cloud SQL Proxy: ${proxyPath} ${proxyArgs.join(" ")}`);
  }

  const proxyProcess = spawnWithCleanEnv(proxyPath, proxyArgs, {
    stdio: debug ? "inherit" : "pipe",
    env: createCleanChildEnv(),
  });

  // Wait for the proxy to start and become ready
  await new Promise<void>((resolve) => {
    const timeout = setTimeout(() => {
      resolve();
    }, 2000);

    let output = "";
    if (proxyProcess.stdout) {
      proxyProcess.stdout.on("data", (data: Buffer) => {
        output += data.toString();
        if (
          output.includes("Ready for new connections") ||
          output.includes("ready")
        ) {
          clearTimeout(timeout);
          resolve();
        }
      });
    }
    if (proxyProcess.stderr) {
      proxyProcess.stderr.on("data", (data: Buffer) => {
        output += data.toString();
        if (
          output.includes("Ready for new connections") ||
          output.includes("ready")
        ) {
          clearTimeout(timeout);
          resolve();
        }
      });
    }

    proxyProcess.on("error", (error: Error) => {
      clearTimeout(timeout);
      print2(`Error: Failed to start Cloud SQL Proxy. ${error.message}`);
      print2("Please ensure gcloud is properly installed and configured.");
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
    password = (
      await asyncSpawn({ debug: false }, tokenCommand, tokenArgs)
    ).trim();
    if (debug) {
      print2("Generated CloudSQL login token.");
    }
  } catch {
    if (debug) {
      print2(
        "Token generation failed. Continuing without IAM login token (may use default authentication)."
      );
    }
    password = "";
  }

  // Connect psql to localhost:localPort
  const sslMode = ssl ? "require" : "disable";
  const connectionString = `host=localhost port=${localPort} dbname=${details.database} user=${dbUser} sslmode=${sslMode}`;

  const env = { ...process.env };
  if (password) {
    env.PGPASSWORD = password;
  }

  if (debug) {
    print2(
      `Connecting psql to localhost:${localPort}/${details.database} as ${dbUser}`
    );
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
    // Clean up: kill the proxy process when psql exits
    if (proxyProcess && !proxyProcess.killed) {
      if (debug) {
        print2("Stopping Cloud SQL Proxy...");
      }
      proxyProcess.kill();
    }
  }
};

/**
 * Prints GCP CloudSQL connection details and keeps Cloud SQL Proxy running
 */
export const printGcpConnectionDetails = async (
  details: GcpConnectionDetails,
  dbUser: string,
  ssl?: boolean,
  debug?: boolean
): Promise<void> => {
  print2("Setting up Cloud SQL Proxy...");
  print2("");

  // Set the GCP project first (this uses gcloud config, not auth)
  print2(`Setting GCP project to ${details.projectId}...`);
  await setGcloudProject(details.projectId, debug);

  // Check if required APIs are enabled (warn user if not)
  await checkGcpApisEnabled(details.projectId, debug);

  // Cloud SQL Proxy uses application-default credentials
  // Check if ADC is set up, and if not, prompt for login
  try {
    const { command: adcCommand, args: adcArgs } = gcloudCommandArgs([
      "auth",
      "application-default",
      "print-access-token",
    ]);
    await asyncSpawn({ debug: false }, adcCommand, adcArgs);
    if (debug) {
      print2("Application-default credentials are already set up.");
    }
  } catch {
    print2("Setting up Google Cloud credentials for Cloud SQL Proxy...");
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
          reject(
            new Error(
              `gcloud auth application-default login exited with code ${code}`
            )
          );
        }
      });
      loginChild.on("error", (error) => {
        reject(error);
      });
    });
    print2("Credentials set up successfully.");
  }

  const proxyPath = await ensureCloudSqlProxy(debug);
  const localPort = 5433;
  const instanceConnectionName = details.instanceConnectionName;
  const proxyArgs = [`-instances=${instanceConnectionName}=tcp:${localPort}`];

  if (debug) {
    print2(`Starting Cloud SQL Proxy: ${proxyPath} ${proxyArgs.join(" ")}`);
  }

  const proxyProcess = spawnWithCleanEnv(proxyPath, proxyArgs, {
    stdio: debug ? "inherit" : "pipe",
    env: createCleanChildEnv(),
  });

  // Set up cleanup handlers
  const cleanupProxy = () => {
    if (proxyProcess && !proxyProcess.killed) {
      if (debug) {
        print2("Cleaning up Cloud SQL Proxy...");
      }
      proxyProcess.kill();
    }
  };

  process.on("SIGINT", cleanupProxy);
  process.on("SIGTERM", cleanupProxy);
  process.on("exit", cleanupProxy);

  // Wait for proxy to be ready
  await new Promise<void>((resolve) => {
    const timeout = setTimeout(() => {
      resolve();
    }, 2000);

    let output = "";
    if (proxyProcess.stdout) {
      proxyProcess.stdout.on("data", (data: Buffer) => {
        output += data.toString();
        if (
          output.includes("Ready for new connections") ||
          output.includes("ready")
        ) {
          clearTimeout(timeout);
          resolve();
        }
      });
    }
    if (proxyProcess.stderr) {
      proxyProcess.stderr.on("data", (data: Buffer) => {
        output += data.toString();
        if (
          output.includes("Ready for new connections") ||
          output.includes("ready")
        ) {
          clearTimeout(timeout);
          resolve();
        }
      });
    }

    proxyProcess.on("error", (error: Error) => {
      clearTimeout(timeout);
      print2(`Error: Failed to start Cloud SQL Proxy. ${error.message}`);
      process.removeListener("SIGINT", cleanupProxy);
      process.removeListener("SIGTERM", cleanupProxy);
      process.removeListener("exit", cleanupProxy);
      sys.exit(1);
    });
  });

  // Generate login token
  const { command: tokenCommand, args: tokenArgs } = gcloudCommandArgs([
    "sql",
    "generate-login-token",
    "--project",
    details.projectId,
  ]);

  let password: string;
  try {
    password = (
      await asyncSpawn({ debug: false }, tokenCommand, tokenArgs)
    ).trim();
    if (!password) {
      throw new Error("Token generation returned empty result");
    }
    if (debug) {
      print2("Generated CloudSQL login token successfully.");
    }
  } catch (error) {
    process.removeListener("SIGINT", cleanupProxy);
    process.removeListener("SIGTERM", cleanupProxy);
    process.removeListener("exit", cleanupProxy);
    cleanupProxy();
    print2(`Error: Failed to generate CloudSQL login token. ${String(error)}`);
    throw error;
  }

  // Construct postgresql:// URL
  const sslMode = ssl ? "require" : "disable";
  const connectionUrl = `postgresql://${encodeURIComponent(dbUser)}:${encodeURIComponent(password)}@localhost:${localPort}/${encodeURIComponent(details.database)}?sslmode=${sslMode}`;

  // Prepare connection details for clipboard
  const connectionDetailsText = `Host: localhost
Port: ${localPort}
Database: ${details.database}
Username: ${dbUser}
Password: ${password}
SSL Mode: ${sslMode}

Connection URL:
${connectionUrl}`;

  const operatingSystem = getOperatingSystem();

  try {
    // Print connection details
    print2("");
    print2("═══════════════════════════════════════════════════════════════");
    print2("  POSTGRES CONNECTION DETAILS");
    print2("═══════════════════════════════════════════════════════════════");
    print2(`  Host:     localhost`);
    print2(`  Port:     ${localPort}`);
    print2(`  Database: ${details.database}`);
    print2(`  Username: ${dbUser}`);
    print2(`  Password: ${password}`);
    print2(
      `  SSL Mode: ${sslMode}${ssl ? "" : " (Cloud SQL Proxy provides encryption)"}`
    );
    print2("");
    print2("Connection URL:");
    print2(`  ${connectionUrl}`);
    print2("═══════════════════════════════════════════════════════════════");
    print2("");

    // Copy connection details to clipboard (macOS)
    if (operatingSystem === "mac") {
      try {
        const copyProcess = spawnWithCleanEnv("pbcopy", [], {
          stdio: "pipe",
          env: createCleanChildEnv(),
        });
        copyProcess.stdin?.write(connectionDetailsText);
        copyProcess.stdin?.end();
        await new Promise<void>((resolve) => {
          copyProcess.on("exit", () => resolve());
          copyProcess.on("error", () => resolve());
        });
        print2("✓ Connection details copied to clipboard!");
        print2("");
      } catch (error) {
        if (debug) {
          print2(`Warning: Failed to copy to clipboard: ${String(error)}`);
        }
      }
    }

    print2(`Cloud SQL Proxy is running on localhost:${localPort}.`);
    print2("The proxy will stop when you close this terminal or press Ctrl+C.");
    print2("");
    print2("Use these details with psql or any PostgreSQL client.");
    print2("");
    print2("Press Ctrl+C to stop the Cloud SQL Proxy and exit.");
    print2("");

    // Wait for user to exit (Ctrl+C will trigger SIGINT handler)
    await new Promise<void>((resolve) => {
      const onExit = () => {
        process.removeListener("SIGINT", onExit);
        process.removeListener("SIGTERM", onExit);
        resolve();
      };
      process.on("SIGINT", onExit);
      process.on("SIGTERM", onExit);
    });
  } finally {
    // Remove signal handlers
    process.removeListener("SIGINT", cleanupProxy);
    process.removeListener("SIGTERM", cleanupProxy);
    process.removeListener("exit", cleanupProxy);

    // Clean up proxy
    cleanupProxy();
  }
};
