import { awsCommand } from "./commands/aws";
import { loginCommand } from "./commands/login";
import { lsCommand } from "./commands/ls";
import { requestCommand } from "./commands/request";
import { sshCommand } from "./commands/ssh";
import { sys } from "typescript";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

const VERSION = "0.2.0";

export const main = () => {
  const commands = [
    awsCommand,
    loginCommand,
    lsCommand,
    requestCommand,
    sshCommand,
  ];
  void commands
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
    })
    .parse();
};

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(err);
    sys.exit(1);
  }
}
