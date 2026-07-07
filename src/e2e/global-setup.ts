/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { E2E_ORG, P0_LAUNCHER, REPO_ROOT, runCommand, runP0 } from "./harness";
import * as fs from "node:fs";
import * as path from "node:path";

/** Runs after the whole suite. The flow spec leaves its access grants in
 * place, and a re-run only exercises fresh requests once they are gone. */
const teardown = () => {
  process.stderr.write(
    `\n[e2e] Reminder: please revoke all access granted to the e2e user in the "${E2E_ORG}" org before running the suite again, so the next run requests access from scratch.\n`
  );
};

/** Prepares the suite: smoke-tests the existing build via `p0 --version` (run
 * `yarn build` yourself first if `build/dist` is stale or missing), then logs
 * in to the e2e org. A failure of either step aborts the whole run.
 *
 * Set P0_E2E_SKIP_SETUP=1 to reuse the existing login session when iterating
 * on individual specs. */
export default async function globalSetup() {
  if (process.env.P0_E2E_SKIP_SETUP) {
    process.stderr.write(
      "[e2e] P0_E2E_SKIP_SETUP is set; reusing existing login\n"
    );
    return teardown;
  }

  const version = await runP0(["--version"], { timeoutMs: 60_000 });
  const { version: packageVersion } = JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8")
  ) as { version: string };
  if (version.code !== 0 || !version.stdout.includes(packageVersion)) {
    throw new Error(
      `[e2e] p0 --version did not report ${packageVersion}\n${version.output}`
    );
  }

  // Interactive so a first-time browser/device login flow can complete; a
  // no-op when a valid session already exists.
  const login = await runCommand(
    "node",
    ["--no-deprecation", P0_LAUNCHER, "login", E2E_ORG],
    { interactive: true, timeoutMs: 5 * 60 * 1000 }
  );
  if (login.code !== 0) {
    throw new Error(
      `[e2e] p0 login ${E2E_ORG} failed with exit code ${login.code}`
    );
  }

  return teardown;
}
