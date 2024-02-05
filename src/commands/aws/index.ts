import { sts } from "./sts";
import yargs from "yargs";

const awsCommands = [sts];

const awsArgs = (yargs: yargs.Argv) => {
  const base = yargs
    .option("account", {
      type: "string",
      describe: "AWS account ID or alias (or set P0_AWS_ACCOUNT)",
    })
    .env("P0_AWS");
  return awsCommands.reduce((m, c) => c(m), base).demandCommand(1);
};

export const awsCommand = (yargs: yargs.Argv) =>
  yargs.command("aws", "Execute AWS commands", awsArgs);
