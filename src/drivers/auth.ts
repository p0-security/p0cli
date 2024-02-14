import { login } from "../commands/login";
import { Authn, Identity } from "../types/identity";
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

export const cached = async <T>(
  name: string,
  loader: () => Promise<T>,
  options: { duration: number }
) => {
  const loc = path.join(
    path.dirname(IDENTITY_FILE_PATH),
    "cache",
    `${name}.json`
  );

  const loadCache = async () => {
    const data = await loader();
    if (!data) throw `Could not load credentials for "${name}"`;
    await fs.mkdir(path.dirname(loc), { recursive: true, mode: "700" });
    await fs.writeFile(loc, JSON.stringify(data), { mode: "600" });
    return data;
  };

  try {
    const stat = await fs.stat(loc);
    if (stat.mtime.getTime() < Date.now() - options.duration) {
      await fs.rm(loc);
      return await loadCache();
    }
    const data = await fs.readFile(loc);
    return JSON.parse(data.toString("utf-8"));
  } catch (error: any) {
    if (error?.code !== "ENOENT")
      console.error(
        `Could not load credentials "${name}" from cache: ${error.message ?? error}`
      );
    return await loadCache();
  }
};

export const loadCredentials = async (options?: {
  noRefresh?: boolean;
}): Promise<Identity> => {
  try {
    const buffer = await fs.readFile(IDENTITY_FILE_PATH);
    const identity: Identity = JSON.parse(buffer.toString());
    if (
      !options?.noRefresh &&
      identity.credential.expires_at < Date.now() * 1e-3
    ) {
      await login({ org: identity.org.slug }, { skipAuthenticate: true });
      console.error("\u200B"); // Force a new line
      return loadCredentials({ noRefresh: true });
    }
    return identity;
  } catch (error: any) {
    if (error?.code === "ENOENT") {
      throw "Please run `p0 login <organization>` to use the P0 CLI.";
    }
    throw error;
  }
};

export const authenticate = async (options?: {
  noRefresh?: boolean;
}): Promise<Authn> => {
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
