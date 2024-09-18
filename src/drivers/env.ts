/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import dotenv from "dotenv";

dotenv.config();

const { env } = process;

export const config = {
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
    clientSecret:
      env.P0_GOOGLE_OIDC_CLIENT_SECRET ?? "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",
  },
  appUrl: env.P0_APP_URL ?? "https://api.p0.app",
  ENV: env.P0_ENV ?? "production",
};
