import { config } from "./env";
import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import {
  collection as fsCollection,
  CollectionReference,
  doc as fsDoc,
  DocumentReference,
  getFirestore,
  terminate,
} from "firebase/firestore";

// Your web app's Firebase configuration
const firebaseConfig = config.fs;

// Initialize Firebase
const app = initializeApp(firebaseConfig);
export const FIRESTORE = getFirestore(app);
export const auth = getAuth();

export const collection = <T>(path: string, ...pathSegments: string[]) => {
  return fsCollection(
    FIRESTORE,
    path,
    ...pathSegments
  ) as CollectionReference<T>;
};
export const doc = <T>(path: string) => {
  return fsDoc(FIRESTORE, path) as DocumentReference<T>;
};

/** Ensures that Firestore is shutdown at command termination
 *
 * This prevents Firestore from holding the command on execution completion or failure.
 */
export const guard =
  <P, T>(cb: (args: P) => Promise<T>) =>
  async (args: P) => {
    try {
      await cb(args);
    } finally {
      void terminate(FIRESTORE);
    }
  };
