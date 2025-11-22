/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { PermissionSpec } from "./request";

// AWS RDS request type
export type AwsPsqlRequest = {
  resource: {
    rdsHost: string;
    region: string;
    port: number;
    database: string;
    ssoStartUrl: string;
    ssoRegion: string;
    ssoAccountId: string;
    roleName: string;
  };
  type: "aws";
};

// GCP CloudSQL request type
export type GcpPsqlRequest = {
  resource: {
    projectId: string;
    instanceConnectionName: string;
    region: string;
    port: number;
    database: string;
    instanceName: string;
  };
  type: "gcp";
};

// Union type for both providers
export type PsqlRequest = AwsPsqlRequest | GcpPsqlRequest;

// Permission spec can be either AWS or GCP
export type PsqlPermissionSpec = 
  | PermissionSpec<"psql", AwsPsqlRequest, PsqlGenerated>
  | PermissionSpec<"psql", GcpPsqlRequest, PsqlGenerated>;

export type PsqlGenerated = {
  username?: string;
};

export type PsqlCommandArgs = {
  debug?: boolean;
  destination: string;
  reason?: string;
  role: string;
  duration?: string;
};

