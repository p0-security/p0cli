export type ClientRegistrationInfo = {
  authorizationEndpoint: string;
  clientId: string;
  clientIdIssuedAt: number;
  clientSecret: string;
  clientSecretExpiresAt: number;
  tokenEndpoint: string;
};

/**
 * AWS OIDC token response uses camelCase instead of snake_case
 */
export type AWSTokenResponse = {
  accessToken: string;
  expiresIn: number;
  idToken: string;
  refreshToken: string;
  tokenType: string;
};
