import yargs from "yargs";

export const failure = async (spec: yargs.Argv, command: string) => {
  let error: any;
  try {
    await spec.fail((_, err) => (error = err)).parse(command);
  } catch (thrown: any) {
    error = thrown;
  }
  return error;
};
