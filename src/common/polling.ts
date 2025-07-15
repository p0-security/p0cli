import { print2 } from "../drivers/stdio";
import stableStringify from "json-stable-stringify";

type PollingOptions<T> = {
  fetcher: () => Promise<T>;
  onChange: (data: T) => void;
  retryOnError?: boolean;
  intervalMs?: number;
  timeoutMs?: number;
  rejectMessage?: string;
};

export function pollChanges<T>({
  fetcher,
  onChange,
  retryOnError = true,
  intervalMs = 100,
}: PollingOptions<T>) {
  let data: T | undefined = undefined;
  const poll = async () => {
    try {
      const responseData = await fetcher();
      if (
        !data ||
        (data && stableStringify(data) !== stableStringify(responseData))
      ) {
        data = responseData;
        onChange(responseData);
      }
    } catch (error) {
      if (!retryOnError) {
        if (interval) clearInterval(interval);
        print2(`Error fetching data: ${error}`);
        throw new Error(`Failed to listen to changes`);
      }
    }
  };
  const interval = setInterval(poll, intervalMs);

  return interval;
}
