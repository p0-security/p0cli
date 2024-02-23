/** Copyright © 2024 P0 Security 

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/

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
