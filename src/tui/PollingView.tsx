/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { MyGrant, fetchMyGrant } from "../drivers/api.js";
import { Authn } from "../types/identity.js";
import {
  describeGrant,
  isTerminalStatus,
  statusInfo,
} from "./grant-display.js";
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

type StatusEntry =
  | { kind: "data"; grant: MyGrant }
  | { kind: "error"; error: string }
  | { kind: "loading" };

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
        setEntries((prev) => ({ ...prev, [id]: { kind: "data", grant } }));
        if (isTerminalStatus(grant.status)) return;
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
      return e?.kind === "data" && isTerminalStatus(e.grant.status);
    });

  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold color={allTerminal ? "green" : "cyan"}>
        {allTerminal ? "✓ Request complete" : "● Request submitted"}
      </Text>
      <Box flexDirection="column" marginTop={1}>
        {requestIds.map((id) => (
          <RequestRow key={id} requestId={id} entry={entries[id]} />
        ))}
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
  const info = statusInfo(grant.status);
  const icon = info.terminal ? (info.success ? "✓" : "✗") : "●";
  return (
    <Box flexDirection="column">
      <Box>
        <Text color={info.color} bold={info.terminal}>
          {icon}{" "}
        </Text>
        <Text bold>{describeGrant(grant)}</Text>
      </Box>
      <Box marginLeft={2}>
        <Text color={info.color}>{info.label}</Text>
        <Text dimColor> ({grant.status})</Text>
      </Box>
    </Box>
  );
};
