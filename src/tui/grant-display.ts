/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { MyGrant } from "../drivers/api.js";

export type StatusColor = "cyan" | "gray" | "green" | "red" | "yellow";

/** UI-facing description of a request status. Single source of truth for the
 *  TUI's color, label, and terminal-ness of each backend RequestStatus. */
export type StatusInfo = {
  color: StatusColor;
  label: string;
  /** True when the request has reached a final state and polling can stop. */
  terminal: boolean;
  /** True when the terminal state is a success (DONE/DONE_NOTIFIED). */
  success: boolean;
};

const STATUS_TABLE: Record<string, StatusInfo> = {
  NEW: {
    color: "yellow",
    label: "Pending approval",
    terminal: false,
    success: false,
  },
  PENDING_APPROVAL: {
    color: "yellow",
    label: "Pending approval",
    terminal: false,
    success: false,
  },
  PENDING_APPROVAL_ESCALATED: {
    color: "yellow",
    label: "Pending approval (escalated)",
    terminal: false,
    success: false,
  },
  APPROVED: {
    color: "cyan",
    label: "Approved — provisioning",
    terminal: false,
    success: false,
  },
  APPROVED_NOTIFIED: {
    color: "cyan",
    label: "Approved — provisioning",
    terminal: false,
    success: false,
  },
  STAGED: {
    color: "cyan",
    label: "Provisioning",
    terminal: false,
    success: false,
  },
  DONE: { color: "green", label: "Active", terminal: true, success: true },
  DONE_NOTIFIED: {
    color: "green",
    label: "Active",
    terminal: true,
    success: true,
  },
  DENIED: { color: "red", label: "Denied", terminal: true, success: false },
  DENIED_NOTIFIED: {
    color: "red",
    label: "Denied",
    terminal: true,
    success: false,
  },
  ERRORED: { color: "red", label: "Errored", terminal: true, success: false },
  ERRORED_ERRORED: {
    color: "red",
    label: "Errored",
    terminal: true,
    success: false,
  },
  ERRORED_NOTIFIED: {
    color: "red",
    label: "Errored",
    terminal: true,
    success: false,
  },
  REVOKED: { color: "gray", label: "Revoked", terminal: true, success: false },
  REVOKED_NOTIFIED: {
    color: "gray",
    label: "Revoked",
    terminal: true,
    success: false,
  },
  EXPIRED: { color: "gray", label: "Expired", terminal: true, success: false },
  EXPIRED_NOTIFIED: {
    color: "gray",
    label: "Expired",
    terminal: true,
    success: false,
  },
  REVOKE_SUBMITTED: {
    color: "yellow",
    label: "Revoking",
    terminal: false,
    success: false,
  },
  EXPIRY_SUBMITTED: {
    color: "yellow",
    label: "Expiring",
    terminal: false,
    success: false,
  },
  TIMED_OUT: {
    color: "red",
    label: "Timed out",
    terminal: true,
    success: false,
  },
  TIMED_OUT_NOTIFIED: {
    color: "red",
    label: "Timed out",
    terminal: true,
    success: false,
  },
  CLEANUP_SUBMITTED: {
    color: "yellow",
    label: "Cleaning up",
    terminal: false,
    success: false,
  },
  CLEANED_UP: {
    color: "gray",
    label: "Cleaned up",
    terminal: true,
    success: false,
  },
  CLEANUP_ERRORED: {
    color: "red",
    label: "Cleanup errored",
    terminal: true,
    success: false,
  },
  DRAFT: {
    color: "gray",
    label: "Draft",
    terminal: false,
    success: false,
  },
  TRANSLATED: {
    color: "gray",
    label: "Translating",
    terminal: false,
    success: false,
  },
};

export const statusInfo = (status: string): StatusInfo =>
  STATUS_TABLE[status] ?? {
    color: "gray",
    label: status,
    terminal: false,
    success: false,
  };

export const isTerminalStatus = (status: string): boolean =>
  statusInfo(status).terminal;

/** Best-effort one-line summary used in list rows and headers. */
export const describeGrant = (g: MyGrant): string => {
  const summary = displaySummary(g) || renderPermissionSummary(g.permission);
  return summary
    ? `${g.type} · ${g.access} · ${summary}`
    : `${g.type} · ${g.access}`;
};

/**
 * Pulls a one-line summary from the backend-provided display rows.
 * Concatenates the first one or two visible rows by `content` only, since
 * labels (e.g. "Linux Username", "Role") tend to add noise in the
 * one-line context where the integration name already implies them.
 */
const displaySummary = (g: MyGrant): string => {
  const rows = (g.display?.rows ?? []).filter(
    (r) => !r.isHidden && !!r.content
  );
  if (rows.length === 0) return "";
  return rows
    .slice(0, 2)
    .map((r) => r.content)
    .join(" · ");
};

/** Picks a friendly summary key from an integration-specific permission
 *  payload (resource/name/role/permission/id), or returns "" if none apply. */
export const renderPermissionSummary = (
  perm: Record<string, unknown>
): string => {
  const candidates = ["resource", "name", "role", "permission", "id"];
  for (const k of candidates) {
    const v = perm[k];
    if (typeof v === "string" && v.length > 0) return v;
  }
  return "";
};

/** "expires in 4h" / "expired" / "no expiry" — for grants. */
export const formatExpiry = (g: MyGrant): string => {
  if (!g.expiryTimestamp) return "no expiry";
  const ms = g.expiryTimestamp - Date.now();
  if (ms <= 0) return "expired";
  return `expires in ${formatDurationCompact(ms)}`;
};

/** "5m ago" / "just now" — for timestamps in the past. */
export const formatRelative = (ts: number | undefined): string => {
  if (!ts) return "";
  const ms = Date.now() - ts;
  if (ms < 60_000) return "just now";
  return `${formatDurationCompact(ms)} ago`;
};

export const formatTimestamp = (ts: number | undefined): string =>
  ts ? new Date(ts).toLocaleString() : "—";

/** Largest-unit short form: "30m" / "2h" / "5d". */
const formatDurationCompact = (ms: number): string => {
  const mins = Math.floor(ms / 60_000);
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
};
