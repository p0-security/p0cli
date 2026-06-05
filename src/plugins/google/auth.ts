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
      // stdio is [stdin, stdout, stderr]. We send the child's stdout to OUR
      // stderr instead of inheriting fd 1: `gcloud auth login` writes its
      // human-readable progress to stdout, but this CLI reserves fd 1 for
      // machine-readable output (e.g. access tokens, JSON) that callers parse.
      // Inheriting the child's stdout would interleave gcloud's chatter into
      // that stream and corrupt it, so we redirect it to stderr — where
      // human-facing text belongs.
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
