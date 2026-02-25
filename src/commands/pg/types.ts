/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { PsqlCommandArgs } from "../../types/psql";

/**
 * Command arguments for the pg command
 */
export type PgCommandArgs = PsqlCommandArgs & {
  psql?: boolean;
  url?: boolean;
  ssl?: boolean;
};

/**
 * AWS RDS connection details
 */
export type AwsConnectionDetails = {
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

/**
 * GCP CloudSQL connection details
 */
export type GcpConnectionDetails = {
  provider: "gcp";
  projectId: string;
  instanceConnectionName: string;
  region: string;
  port: number;
  database: string;
  instanceName: string;
  publicIp?: string;
};

/**
 * Union type for provider-specific connection details
 */
export type ConnectionDetails = AwsConnectionDetails | GcpConnectionDetails;
