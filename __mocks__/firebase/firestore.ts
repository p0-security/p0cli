export const doc = jest.fn();

export const getCollection = jest.fn();

export const getDoc = jest.fn();

export const getFirestore = jest.fn().mockReturnValue({});

let snapshotCallbacks: ((snapshot: object) => void)[] = [];

/** Triggerable mock onSnapshot
 *
 * Usage:
 * ```
 *   import { onSnapshot } from "firebase/firestore";
 *
 *   beforeEach(() => {
 *     (onSnapshot as any).clear();
 *   })
 *
 *   test(..., () => {
 *     // call code under test here
 *     (onSnapshot as any).trigger(data)
 *   })
 * ```
 *
 * Note that only one `onSnapshot` may be tested at a time.
 */
export const onSnapshot = Object.assign(
  jest.fn().mockImplementation((_doc, cb) => {
    snapshotCallbacks.push(cb);
    return () => {
      snapshotCallbacks = [];
    };
  }),
  {
    clear: (snapshotCallbacks = []),
    trigger: (snap: any) => {
      for (const cb of snapshotCallbacks) {
        cb({ data: () => snap });
      }
    },
  }
);

export const query = jest.fn();

export const terminate = jest.fn();
