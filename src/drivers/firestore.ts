/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Identity } from "../types/identity";
import { loadConfig } from "./config";
import { bootstrapConfig } from "./env";
import { FirebaseApp, initializeApp } from "firebase/app";
import {
  getAuth,
  OAuthProvider,
  SignInMethod,
  signInWithCredential,
  UserCredential,
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

const bootstrapApp = initializeApp(bootstrapConfig.fs, "bootstrapApp");
const bootstrapFirestore = getFirestore(bootstrapApp);

let app: FirebaseApp;
let firestore: Firestore;

export async function initializeFirebase() {
  if (!firestore) {
    const tenantConfig = await loadConfig();
    app = initializeApp(tenantConfig.fs, "authFirebase");
    firestore = getFirestore(app);
  }
}

const findProviderId = (identity: Identity) => {
  switch (identity.org.ssoProvider) {
    case "google":
      return SignInMethod.GOOGLE;
    case "google-oidc":
      return "oidc.google-oidc";
    default:
      return identity.org.providerId;
  }
};

export async function authenticateToFirebase(
  identity: Identity
): Promise<UserCredential> {
  const { credential } = identity;
  const tenantId = identity.org.tenantId;

  await initializeFirebase();

  const provider = new OAuthProvider(findProviderId(identity));

  const firebaseCredential = provider.credential({
    accessToken: credential.access_token,
    idToken: credential.id_token,
  });

  const auth = getAuth(app);
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

export const bootstrapDoc = <T>(path: string) => {
  return fsDoc(bootstrapFirestore, path) as DocumentReference<T>;
};

/** Ensures that Firestore is shutdown at command termination
 *
 * This prevents Firestore from holding the command on execution completion or failure.
 */
export const fsShutdownGuard =
  <P, T>(cb: (args: P) => Promise<T>) =>
  async (args: P) => {
    try {
      await cb(args);
    } finally {
      shutdownFirebase();
    }
  };

export const shutdownFirebase = () => {
  if (bootstrapFirestore) void terminate(bootstrapFirestore);
  if (firestore) void terminate(firestore);
};
