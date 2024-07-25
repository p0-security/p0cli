import { sleep } from "../util";

const MAX_RETRIES = 3;
const MAX_RETRY_BACK_OFF_TIME = 10000;

export async function retryWithBackOff<T>(
  cb: () => Promise<T>,
  retryPredicate: (error: any) => boolean,
  retries: number = MAX_RETRIES
): Promise<T> {
  try {
    return await cb();
  } catch (error: any) {
    if (retryPredicate(error)) {
      if (retries > 0) {
        await sleep(MAX_RETRY_BACK_OFF_TIME);
        return retryWithBackOff(cb, retryPredicate, retries - 1);
      }
    }
    throw error;
  }
}
