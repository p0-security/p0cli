/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { MyGrant, fetchMyGrants, relinquishGrant } from "../drivers/api.js";
import { Authn } from "../types/identity.js";
import { Box, Text, useInput } from "ink";
import Spinner from "ink-spinner";
import React, { useCallback, useEffect, useState } from "react";

type GrantsViewProps = {
  authn: Authn;
  /** When true, pressing Enter on a grant prompts to relinquish.
   *  When false (view-only mode), the list is read-only. */
  enableRelinquish: boolean;
  debug?: boolean;
  onBack: () => void;
};

type Status =
  | { kind: "confirming"; grant: MyGrant; grants: MyGrant[] }
  | { kind: "error"; error: string }
  | { kind: "loading" }
  | { kind: "ready"; grants: MyGrant[] }
  | { kind: "relinquished"; grant: MyGrant; grants: MyGrant[] }
  | { kind: "relinquishing"; grant: MyGrant; grants: MyGrant[] };

const describeGrant = (g: MyGrant): string => {
  // Best-effort one-line description. Integration-specific renderers live
  // server-side; for MVP we render `<type> · <access>` plus a short summary
  // of the permission payload.
  const permSummary = renderPermissionSummary(g.permission);
  return permSummary
    ? `${g.type} · ${g.access} · ${permSummary}`
    : `${g.type} · ${g.access}`;
};

const renderPermissionSummary = (perm: Record<string, unknown>): string => {
  // Pick a few likely-friendly keys from the integration-specific payload.
  const candidates = ["resource", "name", "role", "permission", "id"];
  for (const k of candidates) {
    const v = perm[k];
    if (typeof v === "string" && v.length > 0) return v;
  }
  return "";
};

const formatExpiry = (g: MyGrant): string => {
  if (!g.expiryTimestamp) return "no expiry";
  const ms = g.expiryTimestamp - Date.now();
  if (ms < 0) return "expired";
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return `expires in ${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `expires in ${hours}h`;
  const days = Math.floor(hours / 24);
  return `expires in ${days}d`;
};

export const GrantsView: React.FC<GrantsViewProps> = ({
  authn,
  enableRelinquish,
  debug,
  onBack,
}) => {
  const [status, setStatus] = useState<Status>({ kind: "loading" });
  const [focusIndex, setFocusIndex] = useState(0);

  const load = useCallback(async () => {
    setStatus({ kind: "loading" });
    try {
      const grants = await fetchMyGrants(authn, debug);
      setStatus({ kind: "ready", grants });
      setFocusIndex(0);
    } catch (err) {
      setStatus({
        kind: "error",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }, [authn, debug]);

  useEffect(() => {
    void load();
  }, [load]);

  useInput((input, key) => {
    if (status.kind === "loading" || status.kind === "relinquishing") return;

    if (status.kind === "confirming") {
      if (input === "y" || (key.return && input === "")) {
        void doRelinquish(status.grant, status.grants);
      } else if (input === "n" || key.escape) {
        setStatus({ kind: "ready", grants: status.grants });
      }
      return;
    }

    if (status.kind === "relinquished") {
      if (key.return || key.escape) void load();
      return;
    }

    if (status.kind === "error") {
      if (key.return || key.escape) onBack();
      return;
    }

    // ready
    const { grants } = status;
    if (key.escape || input === "q") {
      onBack();
      return;
    }
    if (grants.length === 0) return;
    if (key.upArrow || input === "k") {
      setFocusIndex((i) => (i + grants.length - 1) % grants.length);
    } else if (key.downArrow || input === "j") {
      setFocusIndex((i) => (i + 1) % grants.length);
    } else if (key.return && enableRelinquish) {
      const g = grants[focusIndex];
      if (g) setStatus({ kind: "confirming", grant: g, grants });
    }
  });

  const doRelinquish = useCallback(
    async (g: MyGrant, grants: MyGrant[]) => {
      setStatus({ kind: "relinquishing", grant: g, grants });
      try {
        await relinquishGrant(authn, g.requestId, debug);
        setStatus({ kind: "relinquished", grant: g, grants });
      } catch (err) {
        setStatus({
          kind: "error",
          error: err instanceof Error ? err.message : String(err),
        });
      }
    },
    [authn, debug]
  );

  const title = enableRelinquish ? "Relinquish access" : "Granted access";

  if (status.kind === "loading") {
    return (
      <Box paddingX={1}>
        <Text>
          <Spinner type="dots" /> Loading your active grants…
        </Text>
      </Box>
    );
  }

  if (status.kind === "error") {
    return (
      <Box flexDirection="column" paddingX={1}>
        <Text color="red">Error: {status.error}</Text>
        <Text dimColor>Press Enter or Esc to go back.</Text>
      </Box>
    );
  }

  if (status.kind === "confirming") {
    return (
      <Box flexDirection="column" paddingX={1}>
        <Text bold>Relinquish this access?</Text>
        <Box marginTop={1}>
          <Text>{describeGrant(status.grant)}</Text>
        </Box>
        <Box marginTop={1}>
          <Text dimColor>Press y to confirm, n or Esc to cancel.</Text>
        </Box>
      </Box>
    );
  }

  if (status.kind === "relinquishing") {
    return (
      <Box paddingX={1}>
        <Text>
          <Spinner type="dots" /> Relinquishing {describeGrant(status.grant)}…
        </Text>
      </Box>
    );
  }

  if (status.kind === "relinquished") {
    return (
      <Box flexDirection="column" paddingX={1}>
        <Text color="green">✓ Relinquished {describeGrant(status.grant)}</Text>
        <Text dimColor>Press Enter or Esc to refresh.</Text>
      </Box>
    );
  }

  const { grants } = status;
  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold>{title}</Text>
      <Text dimColor>
        {grants.length === 0
          ? "You currently hold no active grants."
          : enableRelinquish
            ? "↑/↓ navigate · Enter to relinquish · q/Esc back"
            : "↑/↓ navigate · q/Esc back"}
      </Text>
      <Box flexDirection="column" marginTop={1}>
        {grants.map((g, i) => {
          const focused = i === focusIndex;
          return (
            <Box key={g.requestId} flexDirection="column">
              <Text color={focused ? "cyan" : undefined}>
                {focused ? "❯ " : "  "}
                {describeGrant(g)}
              </Text>
              <Box marginLeft={2}>
                <Text dimColor>
                  {g.status} · {formatExpiry(g)}
                </Text>
              </Box>
            </Box>
          );
        })}
      </Box>
    </Box>
  );
};
