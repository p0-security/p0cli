/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import * as Sentry from "@sentry/node";

const ENABLED_ENVIRONMENTS = ["stage", "staging", "prod", "production"];

const environment = process.env.NODE_ENV ?? "development";

if (ENABLED_ENVIRONMENTS.includes(environment)) {
  Sentry.init({
    dsn: "https://4b278d15b1764983a29fb0d918cc9550@o4504696266883072.ingest.sentry.io/4504696268849152",
    environment,
  });
}

export default Sentry;
