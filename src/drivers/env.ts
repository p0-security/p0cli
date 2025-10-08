/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { GoogleApplicationConfig } from "../types/org";
import dotenv from "dotenv";

dotenv.config();

const { env } = process;

const versionCheck = env.VERSION_CHECK;

export const defaultConfig: GoogleApplicationConfig = {
  fs: {
    // Falls back to public production Firestore credentials
    apiKey: env.P0_FS_API_KEY ?? "AIzaSyCaL-Ik_l_5tdmgNUNZ4Nv6NuR4o5_PPfs",
    authDomain: env.P0_FS_AUTH_DOMAIN ?? "p0-prod.firebaseapp.com",
    projectId: env.P0_FS_PROJECT_ID ?? "p0-prod",
    storageBucket: env.P0_FS_STORAGE_BUCKET ?? "p0-prod.appspot.com",
    messagingSenderId: env.P0_FS_MESSAGING_SENDER_ID ?? "228132571547",
    appId: env.P0_FS_APP_ID ?? "1:228132571547:web:4da03aeb78add86fe6b93e",
  },
  google: {
    clientId:
      env.P0_GOOGLE_OIDC_CLIENT_ID ??
      "228132571547-kilcq1er15hlbl6mitghttnacp7u58l8.apps.googleusercontent.com",
    // Despite the name, this is not actually "secret" in any sense of the word.
    // Instead, the client is protected by requiring PKCE and defining the redirect URIs.
    // PKCE achieves similar security guarantees for public clients with an on-the-fly
    // generated secret (the code verifier) as the static secret does for confidential clients.
    // See also: https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce
    // In the PKCE flow the client secret is an optional parameter, however, Google's
    // implementation requires it. That's why the "secret" is present here.
    // This "secret" is only used if the organization uses Google Workspace to log in to P0.
    publicClientSecretForPkce:
      env.P0_GOOGLE_OIDC_CLIENT_SECRET ?? "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",
  },
  appUrl: env.P0_APP_URL ?? "https://api.p0.app",
  environment: env.P0_ENV ?? "production",
  contactMessage: "Please contact support@p0.dev for assistance.",
  helpMessage: "For additional support, please contact support@p0.dev.",
  versionCheck: !versionCheck || versionCheck === "true" ? true : false,
};
