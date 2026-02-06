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
import { DbPermissionSpec } from "../../plugins/db/types";
import { Authn } from "../../types/identity";
import { PermissionRequest } from "../../types/request";
import { exec, throwAssertNever } from "../../util";
import { decodeProvisionStatus } from "../shared";
import { request } from "../shared/request";
import { writeAwsConfigProfile, writeAwsTempCredentials } from "./files";
import { sys } from "typescript";
import yargs from "yargs";

// TODO: Move to shared location
type AnyConfig = {
  label?: string;
  state: string;
};

type PgDatabaseConfig = AnyConfig & {
  defaultDb?: string;
  hostname: string;
  port: string;
  hosting: { type: "aws-rds"; databaseArn: string; vpcId: string };
};

type PgConfig = {
  "iam-write": Record<string, PgDatabaseConfig>;
};

type DbResourceKey = "mysql" | "pg2";

type RdsArgs = yargs.ArgumentsCamelCase<{
  arch: "mysql" | "pg";
  database?: string;
  debug?: boolean;
  instance?: string;
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
        "generate-db-auth-token",
        "Generate an RDS database authentication token",
        (y: yargs.Argv<{ account: string | undefined }>) =>
          y
            .option("arch", {
              type: "string",
              choices: ["mysql", "pg"] as const,
              demandOption: true,
              describe: "Database architecture; use 'mysql' for MariaDB",
            })
            .option("role", {
              type: "string",
              demandOption: true,
              describe: "Database role to access",
            })
            .option("instance", {
              type: "string",
              describe: "P0 instance identifier",
            })
            .option("database", {
              type: "string",
              describe: "Database to access",
            })
            .option("debug", {
              type: "boolean",
              describe: "Print debug information.",
            }),
        // TODO: select based on uidLocation
        (argv) => rdsGenerateDbAuthToken(argv, authn)
      )
  );

const argvToResource = (argv: RdsArgs): DbResourceKey =>
  argv.arch === "mysql"
    ? "mysql"
    : argv.arch === "pg"
      ? "pg2"
      : throwAssertNever(argv.arch);

const requestRdsAccess = async (argv: RdsArgs, authn: Authn) => {
  const integration = argvToResource(argv);

  const response = await request("request")<
    PermissionRequest<DbPermissionSpec>
  >(
    {
      $0: argv.$0,
      _: [],
      arguments: [
        integration,
        "role",
        argv.role,
        ...(argv.instance ? ["--instance", argv.instance] : []),
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

const fetchConfig = async (
  argv: RdsArgs,
  access: DbPermissionSpec,
  authn: Authn
) => {
  const { instanceId } = access.permission;
  const install = await fetchIntegrationConfig<{ config: PgConfig }>(
    authn,
    argvToResource(argv),
    argv.debug
  );
  const config = install.config["iam-write"]?.[instanceId];
  if (!config || config.state !== "installed") {
    throw `No instance with ID ${instanceId}`;
  }

  return config;
};

const rdsGenerateDbAuthToken = async (argv: RdsArgs, authn: Authn) => {
  const access = await requestRdsAccess(argv, authn);

  const awsDelegation = access.delegation?.["aws-rds"].delegation?.aws;
  if (!awsDelegation) {
    throw `P0 granted access, but ${access.permission.instanceId} is not a RDS instance.`;
  }

  const awsAuth = await awsCloudAuth(authn, awsDelegation, argv.debug);
  const dbConfig = await fetchConfig(argv, access, authn);
  const port =
    dbConfig.port ??
    (argv.arch === "mysql"
      ? 3306
      : argv.arch === "pg"
        ? 5432
        : throwAssertNever(argv.arch));

  const database = argv.database ?? dbConfig.defaultDb;

  const dbResource = access.delegation["aws-rds"].delegation.aws.permission.arn;

  const { region } = parseArn(dbResource);
  const profileName = `p0_${access.permission.instanceId}`;

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
    dbConfig.hostname,
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

  const pgInstructions = `export PGPASSWORD="${result.stdout}"
  
  psql "host=$\{RDS_HOST} port=${port} sslmode=verify-full sslrootcert=$\{RDS_SSL_CA} ${database ? `dbname=${database} ` : ""}user=${userName}"`;

  const mysqlInstructions = `export MYSQL_PWD="${result.stdout.trim()}"
  
  mysql -h $\{RDS_HOST} --ssl-ca=$\{RDS_SSL_CA} --ssl-verify-server-cert -P ${port} -u ${userName} ${database}`;

  print2(result.stderr);
  print2(`Access your database by exporting the result of this command and executing psql in an environment with network access to the instance.

Ensure that your execution environment has downloaded the RDS SSL certificate authority (see https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html).

If you are executing from CloudShell this will be done for you already, and the CA will be available at \`/certs/global-bundle.pem\`.

On CloudShell, you can execute:

  export RDS_SSL_CA='/certs/global-bundle.pem'
  export RDS_HOST='${dbConfig.hostname}'
  ${argv.arch === "mysql" ? mysqlInstructions : argv.arch === "pg" ? pgInstructions : throwAssertNever(argv.arch)}

`);
  print1(result.stdout);
  if (result.code !== null) sys.exit(result.code);
};
