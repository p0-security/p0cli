/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
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
