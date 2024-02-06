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
};
