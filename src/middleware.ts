import yargs from "yargs";
import { authenticate } from "./drivers/firestore";

export const authenticateMiddleware = async (
  _args: yargs.ArgumentsCamelCase<{}>
) => {
  await authenticate();
};
