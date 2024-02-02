/** Publicly readable organization data */
type OrgData = {
  clientId: string;
  providerId: string;
  providerDomain?: string;
  ssoProvider: "azure-oidc" | "google" | "microsoft" | "google-oidc" | "okta";
  slug: string;
  tenantId: string;
};
