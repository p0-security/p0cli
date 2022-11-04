export const sleep = (timeoutMillis: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, timeoutMillis));

export const noop = () => {};

export const readLine = () =>
  new Promise<string>((resolve) =>
    process.stdin.on("data", (d) => resolve(d.toString()))
  );
