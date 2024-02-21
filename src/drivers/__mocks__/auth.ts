export const authenticate = async () => ({
  identity: {
    credential: {
      access_token: "test-access-token",
    },
    org: {
      ssoProvider: "oidc-pkce",
      providerDomain: "test.okta.com",
      providerType: "okta",
      slug: "test-org",
      tenantId: "test-tenant",
    },
  },
  userCredential: {
    user: {
      tenantId: "test-tenant",
    },
  },
});

export const cached = async (_label: string, callback: () => Promise<any>) =>
  await callback();
