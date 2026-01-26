/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { asyncSpawn } from "../../common/subprocess";
import { print2 } from "../../drivers/stdio";
import { createCleanChildEnv, spawnWithCleanEnv } from "../../util";
import { gcloudCommandArgs } from "./util";

/**
 * Ensures gcloud CLI is authenticated
 *
 * Checks if gcloud is already authenticated. If not, initiates an interactive
 * login flow that opens a browser for authentication.
 *
 * @param debug - Whether to print debug information
 * @throws Error if authentication fails
 */
export const ensureGcloudAuth = async (debug?: boolean): Promise<void> => {
  let needsLogin = false;

  try {
    // Check if gcloud has any authenticated accounts
    // This doesn't require token refresh, so it won't fail in non-interactive mode
    const { command, args } = gcloudCommandArgs([
      "auth",
      "list",
      "--filter=status:ACTIVE",
      "--format=value(account)",
    ]);
    const output = await asyncSpawn({ debug: false }, command, args);
    const hasActiveAccount = output.trim().length > 0;

    if (hasActiveAccount) {
      // Try to verify tokens are valid by attempting to get an access token
      // If this fails, we'll need to refresh/login
      try {
        const { command: tokenCommand, args: tokenArgs } = gcloudCommandArgs([
          "auth",
          "print-access-token",
        ]);
        await asyncSpawn({ debug: false }, tokenCommand, tokenArgs);
        // If we get here, authentication is working
        if (debug) {
          print2("gcloud is already authenticated.");
        }
        return;
      } catch (tokenError) {
        // Tokens expired or need refresh - check error message
        const errorMessage =
          tokenError instanceof Error ? tokenError.message : String(tokenError);
        // If it's a reauthentication error, we need to login
        if (
          errorMessage.includes("Reauthentication failed") ||
          errorMessage.includes("cannot prompt during non-interactive")
        ) {
          needsLogin = true;
          if (debug) {
            print2("gcloud tokens expired, need to refresh authentication.");
          }
        } else {
          // Some other error - might still work, but log it
          if (debug) {
            print2(`gcloud token check failed: ${errorMessage}`);
          }
          // Still try to proceed - the actual command might work
          // If it doesn't, the user will get a clearer error
          return;
        }
      }
    } else {
      // No active accounts, need to login
      needsLogin = true;
      if (debug) {
        print2("No active gcloud accounts found.");
      }
    }
  } catch (error) {
    // Error checking auth status, assume not authenticated
    needsLogin = true;
    if (debug) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      print2(`Error checking gcloud auth status: ${errorMessage}`);
    }
  }

  // Not authenticated or tokens expired, need to login
  if (needsLogin) {
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

/**
 * Sets the gcloud active project
 *
 * Checks the current project and updates it if it differs from the target
 * project ID.
 *
 * @param projectId - The GCP project ID to set as active
 * @param debug - Whether to print debug information
 * @throws Error if project setting fails
 */
export const setGcloudProject = async (
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
    let currentProject: string;
    try {
      currentProject = (
        await asyncSpawn({ debug: false }, getCommand, getArgs)
      ).trim();
    } catch {
      // If getting current project fails, try to set it anyway
      if (debug) {
        print2(
          `Could not get current gcloud project, will set it to: ${projectId}`
        );
      }
      currentProject = "";
    }

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
    const errorMessage = error instanceof Error ? error.message : String(error);
    print2(`Error: Failed to set gcloud project to ${projectId}.`);
    print2(`Details: ${errorMessage}`);
    throw new Error(`Failed to set gcloud project: ${errorMessage}`);
  }
};
