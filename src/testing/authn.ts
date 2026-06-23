/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Authn } from "../types/identity";
import { Config } from "../types/org";

const testOrgConfig = {
  fs: {
    apiKey: "",
    authDomain: "",
    projectId: "",
    storageBucket: "",
    messagingSenderId: "",
    appId: "",
  },
  appUrl: "https://example.com",
  environment: "test",
  contactMessage: "",
  helpMessage: "",
} satisfies Config;

/** Credentials and org are empty; use when tests only need `getToken` or a well-typed `Authn`. */
export const mockAuthn: Authn = {
  getToken: () => Promise.resolve("mock-token"),
  identity: {
    credential: {
      access_token: "",
      id_token: "",
      expires_in: 0,
      expiry: "",
      expires_at: 0,
    },
    org: {
      slug: "test-org",
      tenantId: "tenant-mock",
      auth: { type: "password" },
      config: testOrgConfig,
    },
  },
};
