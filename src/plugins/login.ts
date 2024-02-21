import { TokenResponse } from "../types/oidc";
import { OrgData } from "../types/org";
import { googleLogin } from "./google/login";
import { oktaLogin } from "./okta/login";

export const pluginLoginMap: Record<
  string,
  (org: OrgData) => Promise<TokenResponse>
> = {
  google: googleLogin,
  okta: oktaLogin,
  "oidc-pkce": async (org) => await pluginLoginMap[org.providerType!]!(org),
};
