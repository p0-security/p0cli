/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { getPasswordCredential } from "../plugins/email/login";
import { Identity } from "../types/identity";
import { OrgData } from "../types/org";
import { getContactMessage, loadConfig } from "./config";
import { bootstrapConfig } from "./env";
import { print2 } from "./stdio";
import { EXPIRED_CREDENTIALS_MESSAGE } from "./util";
import { FirebaseApp, FirebaseError, initializeApp } from "firebase/app";
import {
  EmailAuthCredential,
  getAuth,
  OAuthCredential,
  OAuthProvider,
  ProviderId,
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

const findProviderId = (org: OrgData) => {
  switch (org.ssoProvider) {
    case "google":
      return ProviderId.GOOGLE;
    case "google-oidc":
      return "oidc.google-oidc";
    // Assumes password login if no provider present
    // This could also be email magic link sign-in,
    // which is not supported in the P0 CLI.
    case undefined:
      return ProviderId.PASSWORD;
    default:
      return org.providerId;
  }
};

export const signInToTenant = async (
  org: OrgData,
  firebaseCredential: EmailAuthCredential | OAuthCredential,
  options?: {
    debug?: boolean;
  }
): Promise<UserCredential> => {
  const { tenantId } = org;

  await initializeFirebase();

  const auth = getAuth(app);
  auth.tenantId = tenantId;

  let userCredential;
  try {
    userCredential = await signInWithCredential(auth, firebaseCredential);
  } catch (error) {
    if (
      error instanceof FirebaseError &&
      error.code === "auth/invalid-credential"
    ) {
      throw EXPIRED_CREDENTIALS_MESSAGE;
    } else {
      if (options?.debug) {
        if (error instanceof Error) {
          print2(`Authentication error: ${error.message}`);
        } else {
          print2(`Authentication error: ${String(error)}`);
        }
      }
      throw `An unexpected error occurred during authentication.\n${getContactMessage()}`;
    }
  }

  if (!userCredential?.user?.email) {
    throw `Can not sign in: this user has previously signed in with a different identity provider.\n${getContactMessage()}`;
  }

  return userCredential;
};

export const authenticateToFirebase = async (
  identity: Identity,
  options?: {
    debug?: boolean;
  }
): Promise<UserCredential> => {
  const { credential, org } = identity;

  const providerId = findProviderId(org);
  const firebaseCredential =
    providerId === ProviderId.PASSWORD
      ? getPasswordCredential()
      : new OAuthProvider(providerId).credential({
          accessToken: credential.access_token,
          idToken: credential.id_token,
        });

  return await signInToTenant(org, firebaseCredential, options);
};

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
