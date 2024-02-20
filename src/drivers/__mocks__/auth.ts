export const authenticate = async () => ({
  identity: {
    org: {
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
