import { OrgData } from "../../types/org";
import { oidcLogin } from "../okta/login";

/** Logs in to PingOne via OIDC */
export const pingLogin = async (org: OrgData) => 
  oidcLogin(org, "openid email profile");