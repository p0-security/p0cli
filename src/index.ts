import { sys } from "typescript";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import { login } from "./commands/login";

export const main = () =>
  yargs(hideBin(process.argv))
    .command(
      "login [tenant]",
      "Login to p0 using a web browser",
      (yargs) =>
        yargs.positional("tenant", {
          demandOption: true,
          type: "string",
          describe: "Your P0 tenant ID",
        }),
      login
    )
    .strict()
    .demandCommand(1).argv;

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(err);
    sys.exit(1);
  }
}
