import { cli } from "./commands";
import { noop } from "lodash";

export const main = () => {
  // We can suppress output here, as .fail() already prints errors
  void (cli.parse() as any).catch(noop);
};

if (require.main === module) {
  main();
}
