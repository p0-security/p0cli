/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import tsconfigPaths from "vite-tsconfig-paths";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    environment: "node",
    include: ["src/e2e/**/*.e2e.ts"],
    exclude: ["**/node_modules/**", "**/build/**"],
    globals: true,
    globalSetup: ["src/e2e/global-setup.ts"],
    reporters: ["verbose"],

    // These tests drive real cloud access against the e2e org and share one
    // login session, so everything runs strictly one test at a time. Each
    // spec assumes the global-setup login.
    fileParallelism: false,
    maxConcurrency: 1,
    pool: "forks",
    poolOptions: { forks: { singleFork: true } },

    // SSH access propagation alone can take up to ~10 minutes per provider.
    testTimeout: 20 * 60 * 1000,
    hookTimeout: 5 * 60 * 1000,

    // These tests drive real cloud infra and hit occasional transient
    // failures (propagation timing, intermittent connection errors), so
    // retry before failing the run.
    retry: 3,
  },
});
