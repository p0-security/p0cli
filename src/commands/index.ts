import { awsCommand } from "./aws";
import { loginCommand } from "./login";
import { lsCommand } from "./ls";
import { requestCommand } from "./request";
import { sshCommand } from "./ssh";
import { VERSION } from "lodash";
import { sys } from "typescript";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

const commands = [
  awsCommand,
  loginCommand,
  lsCommand,
  requestCommand,
  sshCommand,
];

export const cli = commands
  .reduce((m, c) => c(m), yargs(hideBin(process.argv)))
  .strict()
  .version(VERSION)
  .demandCommand(1)
  .fail((message, error, yargs) => {
    if (error) console.error(error);
    else {
      console.error(yargs.help());
      console.error(`\n${message}`);
    }
    sys.exit(1);
  });
