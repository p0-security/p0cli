/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { asyncSpawn } from "../../common/subprocess";
import { print2 } from "../../drivers/stdio";
import { spawnWithCleanEnv } from "../../util";
import { gcloudCommandArgs } from "./util";

export const getGcloudAccessToken = async (): Promise<string> => {
  const { command, args } = gcloudCommandArgs(["auth", "print-access-token"]);
  // Force debug=false otherwise it prints the access token
  return await asyncSpawn({ debug: false }, command, args);
};

const runGcloudLogin = async ({ debug }: { debug?: boolean }) =>
  new Promise<void>((resolve, reject) => {
    print2("Logging in to Google Cloud CLI...");
    const { command, args } = gcloudCommandArgs(["auth", "login"]);
    const child = spawnWithCleanEnv(command, args, {
      // [stdin, stdout, stderr]: route child stdout to OUR stderr (never fd 1)
      stdio: ["inherit", process.stderr, "inherit"],
    });
    child.on("error", (error) =>
      reject(`Failed to run 'gcloud auth login': ${error.message}`)
    );
    child.on("exit", (code) => {
      if (debug) {
        print2(`'gcloud auth login' exited with code ${code}`);
      }
      if (code === 0) {
        resolve();
      } else {
        reject(
          "Google Cloud CLI login failed. Please run 'gcloud auth login' and try again."
        );
      }
    });
  });

export const ensureGcloudLogin = async ({
  debug,
}: { debug?: boolean } = {}): Promise<string> => {
  try {
    const accessToken = await getGcloudAccessToken();
    if (debug) {
      print2("Google Cloud CLI credentials are valid; skipping login.");
    }
    return accessToken;
  } catch {
    await runGcloudLogin({ debug });
    return await getGcloudAccessToken();
  }
};
