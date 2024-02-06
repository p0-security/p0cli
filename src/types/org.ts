/** Publicly readable organization data */
export type OrgData = {
  clientId: string;
  providerId: string;
  providerDomain?: string;
  providerType?: "okta";
  ssoProvider:
    | "azure-oidc"
    | "google"
    | "microsoft"
    | "google-oidc"
    | "okta"
    | "oidc-pkce";
  slug: string;
  tenantId: string;
};
