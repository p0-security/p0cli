import { application } from "../mime";

export const OIDC_HEADERS = {
  Accept: application.JSON,
  "Content-Type": application.X_WWW_FORM_URLENCODED,
};
