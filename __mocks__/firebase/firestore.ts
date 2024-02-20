import { noop } from "lodash";

export const doc = jest.fn();

export const getFirestore = jest.fn().mockReturnValue({});

let snapshotCallbacks: ((snapshot: object) => void)[] = [];

export const onSnapshot = Object.assign(
  jest.fn().mockImplementation((_doc, cb) => {
    snapshotCallbacks.push(cb);
    return noop;
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

export const terminate = jest.fn();
