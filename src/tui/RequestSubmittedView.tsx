/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { MyGrant, fetchMyGrant } from "../drivers/api.js";
import { Authn } from "../types/identity.js";
import { RequestDetails } from "./RequestDetails.js";
import {
  describeGrant,
  isTerminalStatus,
  statusInfo,
} from "./grant-display.js";
import { Box, Text, useInput } from "ink";
import Spinner from "ink-spinner";
import React, { useEffect, useRef, useState } from "react";

const POLL_INTERVAL_MS = 3000;

type Entry =
  | { kind: "data"; grant: MyGrant }
  | { kind: "error"; error: string }
  | { kind: "loading" };

type Props = {
  authn: Authn;
  requestIds: string[];
  debug?: boolean;
  onDismiss: () => void;
};

/**
 * Post-submit screen. When the submission produced exactly one request,
 * we go straight to the unified RequestDetails view. When multiple
 * requests were created (rare, but possible for some compound forms),
 * we render a summary list and let the user drill into each.
 */
export const RequestSubmittedView: React.FC<Props> = (props) => {
  if (props.requestIds.length === 1) {
    return (
      <RequestDetails
        authn={props.authn}
        requestId={props.requestIds[0]!}
        debug={props.debug}
        onBack={props.onDismiss}
        backLabel="Continue"
      />
    );
  }
  return <MultiRequestSummary {...props} />;
};

const MultiRequestSummary: React.FC<Props> = ({
  authn,
  requestIds,
  debug,
  onDismiss,
}) => {
  const [entries, setEntries] = useState<Record<string, Entry>>(() => {
    const init: Record<string, Entry> = {};
    for (const id of requestIds) init[id] = { kind: "loading" };
    return init;
  });
  const [drillId, setDrillId] = useState<string | null>(null);
  const [idx, setIdx] = useState(0);
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
    if (drillId) return;
    if (key.upArrow || input === "k") {
      setIdx((i) => (i + requestIds.length - 1) % requestIds.length);
    } else if (key.downArrow || input === "j") {
      setIdx((i) => (i + 1) % requestIds.length);
    } else if (key.return) {
      const id = requestIds[idx];
      if (id) setDrillId(id);
    } else if (key.escape || input === "q") {
      onDismiss();
    }
  });

  if (drillId) {
    return (
      <RequestDetails
        authn={authn}
        requestId={drillId}
        debug={debug}
        onBack={() => setDrillId(null)}
        backLabel="Back to list"
      />
    );
  }

  const allTerminal =
    requestIds.length > 0 &&
    requestIds.every((id) => {
      const e = entries[id];
      return e?.kind === "data" && isTerminalStatus(e.grant.status);
    });

  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold color={allTerminal ? "green" : "cyan"}>
        {allTerminal ? "✓ Requests complete" : "● Requests submitted"}
      </Text>
      <Text dimColor>↑/↓ navigate · Enter view details · q/Esc dismiss</Text>
      <Box flexDirection="column" marginTop={1}>
        {requestIds.map((id, i) => (
          <Row
            key={id}
            requestId={id}
            entry={entries[id]}
            focused={i === idx}
          />
        ))}
      </Box>
    </Box>
  );
};

const Row: React.FC<{
  requestId: string;
  entry: Entry | undefined;
  focused: boolean;
}> = ({ requestId, entry, focused }) => {
  const marker = focused ? "❯ " : "  ";
  if (!entry || entry.kind === "loading") {
    return (
      <Box>
        <Text color={focused ? "cyan" : undefined} bold={focused}>
          {marker}
          <Spinner type="dots" /> {requestId} — loading status…
        </Text>
      </Box>
    );
  }
  if (entry.kind === "error") {
    return (
      <Box>
        <Text color="red">
          {marker}✗ {requestId} — {entry.error}
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
        <Text color={focused ? "cyan" : undefined} bold={focused}>
          {marker}
        </Text>
        <Text color={info.color} bold={info.terminal}>
          {icon}{" "}
        </Text>
        <Text bold>{describeGrant(grant)}</Text>
      </Box>
      <Box marginLeft={4}>
        <Text color={info.color}>{info.label}</Text>
        <Text dimColor> ({grant.status})</Text>
      </Box>
    </Box>
  );
};
