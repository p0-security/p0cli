import { login } from "../commands/login";
import { Identity } from "../types/identity";
import { auth } from "./firestore";
import {
  OAuthProvider,
  SignInMethod,
  signInWithCredential,
} from "firebase/auth";
import * as fs from "fs/promises";
import * as os from "os";
import * as path from "path";

export const IDENTITY_FILE_PATH = path.join(
  os.homedir(),
  ".p0",
  "identity.json"
);

export const loadCredentials = async (options?: { noRefresh?: boolean }) => {
  try {
    const buffer = await fs.readFile(IDENTITY_FILE_PATH);
    const identity: Identity = JSON.parse(buffer.toString());
    if (
      !options?.noRefresh &&
      identity.credential.expires_at < Date.now() * 1e-3
    ) {
      await login({ org: identity.org.slug }, { skipAuthenticate: true });
      console.error("\u200B"); // Force a new line
    }
    return identity;
  } catch (error: any) {
    if (error?.code === "ENOENT") {
      throw "Please run `p0 login <organization>` to use the P0 CLI.";
    }
    throw error;
  }
};

export const authenticate = async (options?: { noRefresh?: boolean }) => {
  const identity = await loadCredentials(options);
  const { credential } = identity;
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
  auth.tenantId = identity.org.tenantId;
  const userCredential = await signInWithCredential(auth, firebaseCredential);
  return { userCredential, identity };
};
