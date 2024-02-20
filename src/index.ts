import { cli } from "./commands";
import { sys } from "typescript";

export const main = () => {
  void cli.parse();
};

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(err);
    sys.exit(1);
  }
}
