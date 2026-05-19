/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { MyGrant, fetchMyGrant } from "../drivers/api.js";
import { Authn } from "../types/identity.js";
import { Box, Text, useInput } from "ink";
import Spinner from "ink-spinner";
import React, { useEffect, useRef, useState } from "react";

type PollingViewProps = {
  authn: Authn;
  requestIds: string[];
  debug?: boolean;
  /** Called when the user dismisses the view (Esc / Enter). */
  onDismiss: () => void;
};

const POLL_INTERVAL_MS = 3000;

// Terminal statuses where polling should stop. Match the backend's
// ResolvedRequestStatuses plus the post-grant "done" variants.
const TERMINAL_STATUSES = new Set([
  "DONE",
  "DONE_NOTIFIED",
  "DENIED",
  "DENIED_NOTIFIED",
  "ERRORED",
  "ERRORED_ERRORED",
  "ERRORED_NOTIFIED",
  "REVOKED",
  "REVOKED_NOTIFIED",
  "EXPIRED",
  "EXPIRED_NOTIFIED",
  "TIMED_OUT",
  "TIMED_OUT_NOTIFIED",
]);

type StatusEntry =
  | { kind: "data"; grant: MyGrant }
  | { kind: "error"; error: string }
  | { kind: "loading" };

type StatusMessage = {
  /** Color hint for the inline rendering. */
  color: "cyan" | "gray" | "green" | "red" | "yellow";
  /** Human label like "Awaiting approval". */
  label: string;
  /** True when this is a terminal state. */
  terminal: boolean;
  /** True when this is a successful terminal state. */
  success?: boolean;
};

const statusToMessage = (status: string): StatusMessage => {
  switch (status) {
    case "NEW":
    case "PENDING_APPROVAL":
    case "PENDING_APPROVAL_ESCALATED":
      return { color: "yellow", label: "Awaiting approval", terminal: false };
    case "APPROVED":
    case "APPROVED_NOTIFIED":
      return {
        color: "cyan",
        label: "Approved — provisioning access",
        terminal: false,
      };
    case "STAGED":
      return { color: "cyan", label: "Provisioning access", terminal: false };
    case "DONE":
    case "DONE_NOTIFIED":
      return {
        color: "green",
        label: "Access granted",
        terminal: true,
        success: true,
      };
    case "DENIED":
    case "DENIED_NOTIFIED":
      return { color: "red", label: "Request denied", terminal: true };
    case "ERRORED":
    case "ERRORED_ERRORED":
    case "ERRORED_NOTIFIED":
      return { color: "red", label: "Request errored", terminal: true };
    case "REVOKED":
    case "REVOKED_NOTIFIED":
      return { color: "gray", label: "Access revoked", terminal: true };
    case "EXPIRED":
    case "EXPIRED_NOTIFIED":
      return { color: "gray", label: "Access expired", terminal: true };
    case "REVOKE_SUBMITTED":
      return { color: "yellow", label: "Revoke pending", terminal: false };
    case "EXPIRY_SUBMITTED":
      return { color: "yellow", label: "Expiry pending", terminal: false };
    case "TIMED_OUT":
    case "TIMED_OUT_NOTIFIED":
      return { color: "red", label: "Request timed out", terminal: true };
    default:
      return { color: "gray", label: status, terminal: false };
  }
};

const describeGrant = (g: MyGrant): string => {
  // Short summary; matches the GrantsView formatter intent.
  const candidates = ["resource", "name", "role", "permission", "id"];
  let summary = "";
  for (const k of candidates) {
    const v = g.permission[k];
    if (typeof v === "string" && v.length > 0) {
      summary = v;
      break;
    }
  }
  return summary
    ? `${g.type} · ${g.access} · ${summary}`
    : `${g.type} · ${g.access}`;
};

export const PollingView: React.FC<PollingViewProps> = ({
  authn,
  requestIds,
  debug,
  onDismiss,
}) => {
  const [entries, setEntries] = useState<Record<string, StatusEntry>>(() => {
    const init: Record<string, StatusEntry> = {};
    for (const id of requestIds) init[id] = { kind: "loading" };
    return init;
  });
  const cancelledRef = useRef(false);

  useEffect(() => {
    cancelledRef.current = false;
    const timers: ReturnType<typeof setTimeout>[] = [];

    const pollOne = async (id: string): Promise<void> => {
      if (cancelledRef.current) return;
      try {
        const grant = await fetchMyGrant(authn, id, debug);
        if (cancelledRef.current) return;
        setEntries((prev) => ({
          ...prev,
          [id]: { kind: "data", grant },
        }));
        if (TERMINAL_STATUSES.has(grant.status)) return;
      } catch (err) {
        if (cancelledRef.current) return;
        setEntries((prev) => ({
          ...prev,
          [id]: {
            kind: "error",
            error: err instanceof Error ? err.message : String(err),
          },
        }));
      }
      // Schedule the next poll. Stored so we can cancel on unmount.
      timers.push(setTimeout(() => void pollOne(id), POLL_INTERVAL_MS));
    };

    for (const id of requestIds) void pollOne(id);

    return () => {
      cancelledRef.current = true;
      for (const t of timers) clearTimeout(t);
    };
  }, [authn, debug, requestIds]);

  useInput((input, key) => {
    if (key.return || key.escape || input === "q") onDismiss();
  });

  const allTerminal =
    requestIds.length > 0 &&
    requestIds.every((id) => {
      const e = entries[id];
      return e?.kind === "data" && statusToMessage(e.grant.status).terminal;
    });

  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold color={allTerminal ? "green" : "cyan"}>
        {allTerminal ? "✓ Request complete" : "● Request submitted"}
      </Text>
      <Box flexDirection="column" marginTop={1}>
        {requestIds.map((id) => {
          const entry = entries[id];
          return <RequestRow key={id} requestId={id} entry={entry} />;
        })}
      </Box>
      <Box marginTop={1}>
        <Text dimColor>
          {allTerminal
            ? "Press Enter or Esc to continue"
            : `Polling every ${POLL_INTERVAL_MS / 1000}s — Enter/Esc to dismiss (request will continue in the background)`}
        </Text>
      </Box>
    </Box>
  );
};

const RequestRow: React.FC<{
  requestId: string;
  entry: StatusEntry | undefined;
}> = ({ requestId, entry }) => {
  if (!entry || entry.kind === "loading") {
    return (
      <Box>
        <Text>
          <Spinner type="dots" /> {requestId} — loading status…
        </Text>
      </Box>
    );
  }
  if (entry.kind === "error") {
    return (
      <Box>
        <Text color="red">
          ✗ {requestId} — {entry.error}
        </Text>
      </Box>
    );
  }
  const { grant } = entry;
  const msg = statusToMessage(grant.status);
  const icon = msg.terminal ? (msg.success ? "✓" : "✗") : "●";
  return (
    <Box flexDirection="column">
      <Box>
        <Text color={msg.color} bold={msg.terminal}>
          {icon}{" "}
        </Text>
        <Text bold>{describeGrant(grant)}</Text>
      </Box>
      <Box marginLeft={2}>
        <Text color={msg.color}>{msg.label}</Text>
        <Text dimColor> ({grant.status})</Text>
      </Box>
    </Box>
  );
};
