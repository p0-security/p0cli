/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Identity } from "../types/identity";
import { tenantConfig } from "./config";
import { bootstrapConfig } from "./env";
import { FirebaseOptions, initializeApp } from "firebase/app";
import {
  Auth,
  getAuth,
  OAuthProvider,
  SignInMethod,
  signInWithCredential,
} from "firebase/auth";
import {
  collection as fsCollection,
  CollectionReference,
  doc as fsDoc,
  DocumentReference,
  getFirestore,
  terminate,
  Firestore,
} from "firebase/firestore";

let firestore: Firestore;
let auth: Auth;

export function initializeFirebase(options?: { useBootstrapConfig: boolean }) {
  const config: FirebaseOptions = options?.useBootstrapConfig
    ? bootstrapConfig.fs
    : tenantConfig.fs;
  const app = initializeApp(config);

  firestore = getFirestore(app);
  auth = getAuth();
}

export async function authenticateToFirebase(identity: Identity) {
  const { credential } = identity;
  const tenantId = identity.org.tenantId;

  // TODO: Move to map lookup
  const provider = new OAuthProvider(
    identity.org.ssoProvider === "google"
      ? SignInMethod.GOOGLE
      : identity.org.providerId
  );

  const firebaseCredential = provider.credential({
    accessToken: credential.access_token,
    idToken: credential.id_token,
  });

  auth.tenantId = tenantId;

  const userCredential = await signInWithCredential(auth, firebaseCredential);

  if (!userCredential?.user?.email) {
    throw "Can not sign in: this user has previously signed in with a different identity provider.\nPlease contact support@p0.dev to enable this user.";
  }

  return userCredential;
}

export const collection = <T>(path: string, ...pathSegments: string[]) => {
  return fsCollection(
    firestore,
    path,
    ...pathSegments
  ) as CollectionReference<T>;
};

export const doc = <T>(path: string) => {
  return fsDoc(firestore, path) as DocumentReference<T>;
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
      void terminate(firestore);
    }
  };
