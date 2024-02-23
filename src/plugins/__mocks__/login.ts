/** Copyright © 2024-present P0 Security 

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/

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
