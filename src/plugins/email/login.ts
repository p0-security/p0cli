/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { signInToTenant } from "../../drivers/firestore";
import { OrgData } from "../../types/org";
import { LoginPlugin, LoginPluginMethods } from "../login";
import { EmailAuthProvider } from "firebase/auth";

export const getPasswordCredential = () => {
  const email = process.env["P0_EMAIL"];
  const password = process.env["P0_PASSWORD"];
  if (!email || !password) {
    throw new Error(
      "Your organization uses email / password login. The P0_EMAIL and P0_PASSWORD environment variables must be set."
    );
  }
  return EmailAuthProvider.credential(email, password);
};

export const emailPasswordLogin: LoginPlugin =
  async (): Promise<LoginPluginMethods> => {
    return {
      login: async (org: OrgData) => {
        const credential = getPasswordCredential();
        const userCredential = await signInToTenant(org, credential, {
          debug: true,
        });
        const idTokenResult = await userCredential.user.getIdTokenResult();
        // expirationTime is in UTC, e.g. "Wed, 14 May 2025 04:07:13 GMT"
        const expiresAt = new Date(idTokenResult.expirationTime).getTime();
        return {
          // Placeholder, do not store the actual password
          // We always read the password from environment variable
          access_token: "PASSWORD",
          id_token: idTokenResult.token,
          expires_in: Math.floor((expiresAt - Date.now()) * 1e-3),
          refresh_token: userCredential.user.refreshToken,
          expiry: idTokenResult.expirationTime,
        };
      },
      renewAccessToken: () => Promise.resolve(undefined),
    };
  };
