/** Publicly readable organization data */
export type OrgData = {
  clientId: string;
  providerId: string;
  providerDomain?: string;
  providerType?: "okta";
  ssoProvider:
    | "azure-oidc"
    | "google-oidc"
    | "google"
    | "microsoft"
    | "oidc-pkce"
    | "okta";
  slug: string;
  tenantId: string;
};
