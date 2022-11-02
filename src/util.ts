export const sleep = (timeoutMillis: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, timeoutMillis));
