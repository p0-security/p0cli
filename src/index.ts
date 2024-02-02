import { awsCommand } from "./commands/aws";
import { loginCommand } from "./commands/login";
import { requestCommand } from "./commands/request";
import { sys } from "typescript";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

const VERSION = "0.2.0";

export const main = () => {
  const commands = [awsCommand, loginCommand, requestCommand];
  commands
    .reduce((m, c) => c(m), yargs(hideBin(process.argv)))
    .strict()
    .version(VERSION)
    .demandCommand(1)
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
