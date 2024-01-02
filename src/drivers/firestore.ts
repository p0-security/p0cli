import {
  collection as fsCollection,
  CollectionReference,
  doc as fsDoc,
  DocumentReference,
  getFirestore,
} from "firebase/firestore";
import { initializeApp } from "firebase/app";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  AuthCredential,
  getAuth,
  GoogleAuthProvider,
  // OAuthCredential,
  OAuthProvider,
  signInWithCredential,
} from "firebase/auth";

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyC9A5VXSwDDS-Vp4WH_UIanEqJvv_7XdlQ",
  authDomain: "p0-gcp-project.firebaseapp.com",
  projectId: "p0-gcp-project",
  storageBucket: "p0-gcp-project.appspot.com",
  messagingSenderId: "398809717501",
  appId: "1:398809717501:web:6dd1cab893b2faeb06fc94",
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
export const FIRESTORE = getFirestore(app);
export const auth = getAuth();

export const IDENTITY_FILE_PATH = path.join(
  os.homedir(),
  ".p0cli",
  "identity.json"
);

export const authenticate = async () => {
  const storedCredential: {
    authCredential: AuthCredential;
    tenantId: string;
    tenant: string;
  } = JSON.parse(fs.readFileSync(IDENTITY_FILE_PATH).toString());
  const creds = OAuthProvider.credentialFromJSON(
    storedCredential.authCredential
  );
  const googleCredential = GoogleAuthProvider.credential(
    creds.idToken,
    creds.accessToken
  );

  auth.tenantId = storedCredential.tenantId;

  const userCredential = await signInWithCredential(auth, googleCredential);

  return { userCredential, storedCredential };
};

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
