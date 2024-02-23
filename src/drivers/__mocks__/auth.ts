/** Copyright © 2024-present P0 Security 

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/
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
