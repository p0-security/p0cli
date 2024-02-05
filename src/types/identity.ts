import { TokenResponse } from "./oidc";
import { OrgData } from "./org";

export type Identity = {
  credential: TokenResponse & { expires_at: number };
  org: OrgData;
};
