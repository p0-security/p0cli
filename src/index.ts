import { sys } from "typescript";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import { login, loginArgs } from "./commands/login";
import { request, requestArgs } from "./commands/request";

const VERSION = "0.1.0";

export const main = () =>
  yargs(hideBin(process.argv))
    .scriptName("p0cli")
    .command<{ tenant: string }>(
      "login <tenant>",
      "Login to p0 using a web browser",
      loginArgs,
      login
    )
    .command<{}>(
      "request <resource> [...arguments]",
      "Manually request permissions on a resource",
      requestArgs,
      request
    )
    .strict()
    .version(VERSION)
    .demandCommand(1).argv;

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(err);
    sys.exit(1);
  }
}
