import { TokenResponse } from "./oidc";
import { OrgData } from "./org";
import { UserCredential } from "firebase/auth";

export type Identity = {
  credential: TokenResponse & { expires_at: number };
  org: OrgData;
};

export type Authn = {
  identity: Identity;
  userCredential: UserCredential;
};
