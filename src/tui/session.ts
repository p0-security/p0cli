/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  authenticate,
  loadCredentials,
  remainingTokenTime,
} from "../drivers/auth/index.js";
import { Authn, Identity } from "../types/identity.js";

/**
 * Snapshot of who the user is right now, taken at TUI mount time.
 *
 * `logged-out` carries a `defaultOrg` so the login screen can pre-fill
 * the org slug from `P0_ORG` / a previous identity. The logged-in
 * identity itself is the source of truth for the org slug — env vars
 * never override an active session.
 */
export type Session =
  | {
      kind: "logged-in";
      authn: Authn;
      orgSlug: string;
      email?: string;
      /** Seconds until the cached OIDC token expires. */
      expiresInSec: number;
    }
  | {
      kind: "logged-out";
      defaultOrg?: string;
      /** Optional message to surface to the user (e.g. "Your session expired"). */
      message?: string;
    };

/**
 * Loads the on-disk identity (if any) and resolves it into a typed
 * session. Failures here are treated as "logged out" — the TUI handles
 * the unauthenticated state explicitly rather than erroring at startup.
 */
export const loadSession = async (debug?: boolean): Promise<Session> => {
  const defaultOrg = await readDefaultOrg();

  const identity = await loadCredentials().catch(() => undefined);
  if (!identity) {
    return { kind: "logged-out", defaultOrg };
  }

  const expiresInSec = remainingTokenTime(identity);
  if (expiresInSec <= 0) {
    return {
      kind: "logged-out",
      defaultOrg: identity.org.slug ?? defaultOrg,
      message: "Your session has expired. Please log in again.",
    };
  }

  // Bring the auth context fully online (firebase, OTel exporter, …).
  // A failure here typically means the token is unusable; fall back to
  // logged-out so the user can re-auth from the TUI.
  let authn: Authn;
  try {
    authn = await authenticate({ debug });
  } catch {
    return {
      kind: "logged-out",
      defaultOrg: identity.org.slug ?? defaultOrg,
      message: "Could not validate your session. Please log in again.",
    };
  }

  return {
    kind: "logged-in",
    authn,
    orgSlug: identity.org.slug,
    email: resolveEmail(authn, identity),
    expiresInSec,
  };
};

/**
 * Best-effort resolution of the user's email for the header display.
 *
 * Tries, in order:
 * 1. Firebase user credential — set when the org goes through Firebase
 *    Auth (the common path; produced by `authenticateToFirebase`).
 *    Always carries the upstream IdP's email (Google, Okta SAML, …).
 * 2. JWT claims on the id_token — universal across every SSO provider
 *    that follows OIDC. Decoded inline (we trust our own credentials;
 *    no signature check needed for a display-only field).
 *
 * Returns undefined if neither path yields a string; the header then
 * falls back to "(unknown user)" but the rest of the TUI is unaffected.
 * The `/account` endpoint can't help here — it only returns org-level
 * metadata (orgName, cloudStack, …), no caller identity.
 */
const resolveEmail = (authn: Authn, identity: Identity): string | undefined => {
  const firebaseEmail = authn.userCredential?.user.email;
  if (typeof firebaseEmail === "string" && firebaseEmail.length > 0) {
    return firebaseEmail;
  }
  return extractEmailFromIdToken(identity.credential.id_token);
};

/**
 * Decodes the `email` claim (or `preferred_username` as a fallback —
 * some Okta deployments only populate that) from an OIDC id_token's
 * payload. Pure base64url + JSON; no crypto, no library. If anything
 * about the token is malformed we return undefined and let the caller
 * fall back.
 */
const extractEmailFromIdToken = (
  idToken: string | undefined
): string | undefined => {
  if (!idToken) return undefined;
  const parts = idToken.split(".");
  if (parts.length < 2 || !parts[1]) return undefined;
  try {
    // base64url → base64 (replace url-safe chars, pad to length % 4).
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
    const json = Buffer.from(padded, "base64").toString("utf8");
    const claims = JSON.parse(json) as Record<string, unknown>;
    const email = claims["email"];
    if (typeof email === "string" && email.length > 0) return email;
    // Some Okta orgs include the user identifier under
    // preferred_username (often the email-like login) when `email` is
    // omitted from the access/ID token claims.
    const preferred = claims["preferred_username"];
    if (typeof preferred === "string" && preferred.length > 0) return preferred;
    return undefined;
  } catch {
    return undefined;
  }
};

/**
 * Decides what to pre-fill in the login form when the user is logged out.
 * Order: P0_ORG env var > previous identity slug (read separately). We
 * don't read the config file here — that's only persisted after a
 * successful login, and the env var is the more authoritative pre-fill
 * source on developer machines.
 */
const readDefaultOrg = async (): Promise<string | undefined> => {
  const fromEnv = process.env.P0_ORG?.trim();
  if (fromEnv) return fromEnv;
  // If a previous identity exists but its token is expired, surface its
  // slug as the default so re-login doesn't make the user re-type.
  const identity = await loadCredentials().catch(() => undefined);
  return identity?.org?.slug;
};

/** Compact "3h27m" / "12m" / "45s" / "expired" formatter for the header. */
export const formatSessionRemaining = (sec: number): string => {
  if (sec <= 0) return "expired";
  const totalSec = Math.floor(sec);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  if (h > 0) return `${h}h${m.toString().padStart(2, "0")}m`;
  if (m > 0) return `${m}m`;
  return `${s}s`;
};
