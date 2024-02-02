type AuthorizeResponse = {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  // Intervals in seconds
  expires_in: number;
  interval: number;
};

type TokenResponse = {
  access_token: string;
  id_token: string;
  token_type: string;
  scope: string;
  expires_in: number;
  refresh_token: string;
  device_secret: string;
  expiry: string;
};

type TokenErrorResponse = {
  error:
    | "missing parameter"
    | "not found"
    | "bad grant type"
    | "slow_down"
    | "authorization_pending"
    | "access_denied"
    | "expired_token";
};
