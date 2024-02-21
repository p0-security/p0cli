export const pluginLoginMap = {
  google: jest.fn().mockResolvedValue({
    access_token: "test-access-token",
    id_token: "test-id-token",
    token_type: "oidc",
    scope: "oidc",
    expires_in: 3600,
    refresh_token: "test-refresh-token",
    device_secret: "test-device-secret",
  }),
};
