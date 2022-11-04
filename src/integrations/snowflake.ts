import yargs from "yargs";
import { authenticateMiddleware } from "../middleware";
import { noop } from "../util";
import permission from "../common/permission";
import { sys } from "typescript";

export const requestArgs = (yargs: yargs.Argv<{}>): yargs.Argv<{}> =>
  yargs.command(
    "snowflake [role|object|query]",
    "Request roles, table-level, or query grants in Snowflake",
    (yargs) =>
      yargs
        .command(
          "role <role>",
          "Request a known role",
          (y) =>
            y
              .positional("role", {
                description: "A pre-existing Snowflake role",
                type: "string",
              })
              .strict(),
          requestRole,
          middlewares
        )
        .command(
          "object [...options] <object>",
          "Request an object-level grant",
          (y) =>
            y
              .positional("object", {
                description:
                  "A fully-qualified Snowflake object (e.g. tables should be DATABASE.SCHEMA.TABLE)",
                type: "string",
              })
              .option("permission", {
                alias: "p",
                description: "A Snowflake permission for this grant",
                type: "string",
                default: "SELECT",
              })
              .option("type", {
                alias: "t",
                description: "The class or type of this object",
                type: "string",
                default: "TABLE",
              }),
          requestTable,
          middlewares
        )
        .command(
          "query <query>",
          "Request all grants needed to execute a query.\n\nCurrently only queries compatible with Postgres SQL are supported.",
          (y) =>
            y.positional("query", {
              description: "One or more Snowflake queries (separate with ;)",
              type: "string",
            }),
          requestQuery,
          middlewares
        )
        .demandCommand(1)
        .strict()
  );

const middlewares = [authenticateMiddleware];

const requestRole = async (
  args: yargs.ArgumentsCamelCase<{ role: string }>
) => {
  await permission.submit("snowflake", { type: "role", roleName: args.role });
  sys.exit(0);
};

const requestTable = (
  _args: yargs.ArgumentsCamelCase<{
    table: string;
    permission: string;
    type: string;
  }>
) => {};

const requestQuery = (_args: yargs.ArgumentsCamelCase<{ query: string }>) => {};
