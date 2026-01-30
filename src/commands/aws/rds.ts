/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchIntegrationConfig } from "../../drivers/api";
import { print1, print2 } from "../../drivers/stdio";
import { awsCloudAuth } from "../../plugins/aws/auth";
import { parseArn } from "../../plugins/aws/utils";
import { Pg2PermissionSpec } from "../../plugins/kubeconfig/pg/types";
import { Authn } from "../../types/identity";
import { PermissionRequest } from "../../types/request";
import { exec } from "../../util";
import { decodeProvisionStatus } from "../shared";
import { request } from "../shared/request";
import { writeAwsConfigProfile, writeAwsTempCredentials } from "./files";
import { pick } from "lodash";
import { sys } from "typescript";
import yargs from "yargs";

// TODO: Move to shared location
type AnyConfig = {
  label?: string;
  state: string;
};

type PgDatabaseConfig = AnyConfig & {
  database: string;
  hostname: string;
  port: string;
  hosting: { type: "aws-rds"; databaseArn: string; vpcId: string };
};

type PgConfig = {
  "iam-write": Record<string, PgDatabaseConfig>;
};

type RdsArgs = yargs.ArgumentsCamelCase<{
  database?: string;
  debug?: boolean;
  role: string;
}>;

export const rds = (
  yargs: yargs.Argv<{ account: string | undefined }>,
  authn: Authn
) =>
  yargs.command("rds", "Interact with AWS RDS", (yargs) =>
    yargs
      // this parent command hangs because it doesn't have a handler,
      // while building we'll require an argument which ensures that we'll
      // always correctly display a help message
      .demandCommand(1)
      .command(
        "generate-db-auth-token <role>",
        "Generate an RDS database authentication token",
        (y: yargs.Argv<{ account: string | undefined }>) =>
          y
            .positional("role", {
              type: "string",
              demandOption: true,
              describe: "Database role to access",
            })
            .option("database", {
              type: "string",
              describe: "P0 database identifier",
            })
            .option("debug", {
              type: "boolean",
              describe: "Print debug information.",
            }),
        // TODO: select based on uidLocation
        (argv) => rdsGenerateDbAuthToken(argv, authn)
      )
  );

const requestRdsAccess = async (argv: RdsArgs, authn: Authn) => {
  const response = await request("request")<
    PermissionRequest<Pg2PermissionSpec>
  >(
    {
      ...pick(argv, "$0", "_"),
      arguments: [
        "pg2",
        "role",
        argv.role,
        ...(argv.database ? ["--database", argv.database] : []),
      ],
      wait: true,
    },
    authn,
    { message: "approval-required" }
  );

  if (!response) {
    throw "Did not receive access ID from server";
  }

  const { request: access } = response;

  const code = await decodeProvisionStatus(access);
  if (!code) {
    sys.exit(1);
  }

  return access;
};

const fetchPgConfig = async (
  argv: RdsArgs,
  access: Pg2PermissionSpec,
  authn: Authn
) => {
  const { databaseId } = access.permission;
  const install = await fetchIntegrationConfig<{ config: PgConfig }>(
    authn,
    "pg2",
    argv.debug
  );
  const config = install.config["iam-write"]?.[access.permission.databaseId];
  if (!config || config.state !== "installed") {
    throw `No database with ID ${databaseId}`;
  }

  return config;
};

const rdsGenerateDbAuthToken = async (argv: RdsArgs, authn: Authn) => {
  const access = await requestRdsAccess(argv, authn);

  const awsDelegation = access.delegation?.["aws-rds"].delegation?.aws;
  if (!awsDelegation) {
    throw `P0 granted access, but ${access.permission.databaseId} is not a RDS database.`;
  }

  const awsAuth = await awsCloudAuth(authn, awsDelegation, argv.debug);
  const pgConfig = await fetchPgConfig(argv, access, authn);
  const port = pgConfig.port ?? 5432;

  const dbResource = access.delegation["aws-rds"].delegation.aws.permission.arn;

  const { region } = parseArn(dbResource);
  const profileName = `p0_${access.permission.databaseId}`;

  const userEmailName = access.principal.split("@")[0];

  if (!userEmailName) {
    throw "Could not identify principal for this access.";
  }

  const userName = `p0_${userEmailName.replace(/\W/g, "_").toLowerCase()}`;

  await writeAwsTempCredentials(profileName, awsAuth);
  await writeAwsConfigProfile(profileName, { region });

  const generateTokenArgs = [
    "rds",
    "generate-db-auth-token",
    "--hostname",
    pgConfig.hostname,
    "--port",
    port,
    "--region",
    region,
    "--username",
    userName,
    "--profile",
    profileName,
  ];

  const result = await exec("aws", generateTokenArgs, { check: true });

  print2(result.stderr);
  print2(`Access your database by exporting the result of this command and executing psql in an environment with network access to the instance.

Ensure that your execution environment has downloaded the RDS SSL certificate authority (see https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html).

If you are executing from CloudShell this will be done for you already, and the CA will be available at \`/certs/global-bundle.pem\`.

On CloudShell, you can execute:

  export RDSSSLCA='/certs/global-bundle.pem'
  export RDSHOST='${pgConfig.hostname}'
  export PGPASSWORD='${result.stdout}'

  psql "host=$\{RDSHOST} port=${port} sslmode=verify-full sslrootcert=$\{RDSSSLCA} dbname=${pgConfig.database} user=${userName}"

`);
  print1(result.stdout);
  if (result.code !== null) sys.exit(result.code);
};
