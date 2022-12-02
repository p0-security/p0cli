import yargs from "yargs";
import * as snowflake from "../integrations/snowflake";

const plugins = [snowflake];

export const requestArgs = (yargs: yargs.Argv<{}>) => {
  plugins
    .reduce((y, p) => p.requestArgs(y), yargs)
    .demandCommand(1)
    .strict();
};

export const request = (_args: yargs.ArgumentsCamelCase<{}>) => {};
