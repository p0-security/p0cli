export type AuthorizeRequest = {
  client_id: string;
  code_challenge: string;
  code_challenge_method: "plain" | "S256";
  redirect_uri: string;
  response_type: "code";
  scope: string;
  state?: string;
  login_hint?: string;
};

export type AuthorizeResponse = {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  // Intervals in seconds
  expires_in: number;
  interval: number;
};

export type TokenResponse = {
  access_token: string;
  id_token: string;
  token_type: string;
  scope: string;
  expires_in: number;
  refresh_token: string;
  device_secret: string;
  expiry: string;
};

export type TokenErrorResponse = {
  error:
    | "access_denied"
    | "authorization_pending"
    | "bad grant type"
    | "expired_token"
    | "missing parameter"
    | "not found"
    | "slow_down";
};
