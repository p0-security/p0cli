/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  GrantDisplayRow,
  GrantHistoryEntry,
  MyGrant,
  fetchMyGrant,
} from "../drivers/api.js";
import { Authn } from "../types/identity.js";
import {
  describeGrant,
  formatExpiry,
  formatRelative,
  formatTimestamp,
  isTerminalStatus,
  statusInfo,
} from "./grant-display.js";
import { Box, Text, useInput } from "ink";
import Spinner from "ink-spinner";
import React, { useEffect, useState } from "react";

const POLL_INTERVAL_MS = 3000;
const RELINQUISHABLE_STATUS = "DONE_NOTIFIED";

type DetailsState =
  | { kind: "error"; error: string }
  | { kind: "loading" }
  | { kind: "ready"; grant: MyGrant };

export type RequestDetailsAction = "back" | "relinquish";

type RequestDetailsProps = {
  authn: Authn;
  requestId: string;
  debug?: boolean;
  onBack: () => void;
  /**
   * Optional handler for the Relinquish action. When omitted, the action
   * is hidden — appropriate for the post-submit flow where the user
   * usually doesn't want to immediately give the access back.
   */
  onRelinquish?: (grant: MyGrant) => void;
  /**
   * Override the back action's label (e.g. "Continue" in the post-submit
   * flow vs "Back to list" when navigating from My access).
   */
  backLabel?: string;
};

/**
 * Polls a single permission request and renders its full details: rich
 * rows from the backend display payload, lifecycle history, and the
 * usual metadata (status, principal, timestamps, reason). Used by both
 * the post-submit flow and the "My access" drill-in.
 */
export const RequestDetails: React.FC<RequestDetailsProps> = ({
  authn,
  requestId,
  debug,
  onBack,
  onRelinquish,
  backLabel,
}) => {
  const [state, setState] = useState<DetailsState>({ kind: "loading" });
  const [pollWarning, setPollWarning] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const tick = async () => {
      if (cancelled) return;
      try {
        const grant = await fetchMyGrant(authn, requestId, debug);
        if (cancelled) return;
        setState({ kind: "ready", grant });
        setPollWarning(null);
        if (isTerminalStatus(grant.status)) return;
      } catch (err) {
        if (cancelled) return;
        const message = err instanceof Error ? err.message : String(err);
        setState((prev) =>
          prev.kind === "loading" ? { kind: "error", error: message } : prev
        );
        setPollWarning(message);
      }
      timer = setTimeout(() => void tick(), POLL_INTERVAL_MS);
    };

    void tick();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [authn, debug, requestId]);

  if (state.kind === "loading") {
    return (
      <Box paddingX={1}>
        <Text>
          <Spinner type="dots" /> Loading request {requestId}…
        </Text>
      </Box>
    );
  }
  if (state.kind === "error") {
    return <ErrorScreen error={state.error} onBack={onBack} />;
  }

  return (
    <DetailsContent
      grant={state.grant}
      pollWarning={pollWarning}
      onBack={onBack}
      onRelinquish={onRelinquish}
      backLabel={backLabel}
    />
  );
};

const DetailsContent: React.FC<{
  grant: MyGrant;
  pollWarning: string | null;
  onBack: () => void;
  onRelinquish?: (g: MyGrant) => void;
  backLabel?: string;
}> = ({ grant, pollWarning, onBack, onRelinquish, backLabel }) => {
  const canRelinquish =
    !!onRelinquish && grant.status === RELINQUISHABLE_STATUS;
  const actions: RequestDetailsAction[] = canRelinquish
    ? ["relinquish", "back"]
    : ["back"];
  const [actionIdx, setActionIdx] = useState(0);
  useEffect(() => {
    if (actionIdx >= actions.length) setActionIdx(0);
  }, [actionIdx, actions.length]);

  useInput((input, key) => {
    if (key.upArrow || input === "k") {
      setActionIdx((i) => (i + actions.length - 1) % actions.length);
    } else if (key.downArrow || input === "j") {
      setActionIdx((i) => (i + 1) % actions.length);
    } else if (key.return) {
      const a = actions[actionIdx];
      if (a === "relinquish" && onRelinquish) onRelinquish(grant);
      else if (a === "back") onBack();
    } else if (key.escape || input === "q") {
      onBack();
    }
  });

  const info = statusInfo(grant.status);
  const visibleRows = (grant.display?.rows ?? []).filter(
    (r) => !r.isHidden && !!r.content
  );
  const history = grant.display?.history ?? [];

  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold>{describeGrant(grant)}</Text>
      <Box marginTop={1} flexDirection="column">
        <Field label="Status">
          <Text color={info.color}>● {info.label} </Text>
          <Text dimColor>({grant.status})</Text>
        </Field>
        <Field label="Type">
          <Text>{grant.type}</Text>
        </Field>
        <Field label="Access">
          <Text>{grant.access}</Text>
        </Field>
        <Field label="Requestor">
          <Text>{grant.requestor}</Text>
        </Field>
        <Field label="Principal">
          <Text>
            {grant.principal}
            {grant.principal === grant.requestor ? (
              <Text dimColor> (self)</Text>
            ) : null}
          </Text>
        </Field>
        <Field label="Requested">
          <Text>{formatTimestamp(grant.requestedTimestamp)}</Text>
          <Text dimColor>
            {" · " + formatRelative(grant.requestedTimestamp)}
          </Text>
        </Field>
        <Field label="Granted">
          <Text>{formatTimestamp(grant.grantTimestamp)}</Text>
          {grant.grantTimestamp ? (
            <Text dimColor>{" · " + formatRelative(grant.grantTimestamp)}</Text>
          ) : null}
        </Field>
        <Field label="Expires">
          <Text>
            {formatTimestamp(grant.expiryTimestamp)}
            {grant.expiryTimestamp ? (
              <Text dimColor>{` · ${formatExpiry(grant)}`}</Text>
            ) : null}
          </Text>
        </Field>
        {grant.duration ? (
          <Field label="Duration">
            <Text>{grant.duration}</Text>
          </Field>
        ) : null}
        {grant.reason ? (
          <Field label="Reason">
            <Text>{grant.reason}</Text>
          </Field>
        ) : null}
        {grant.approvalDetails ? (
          <Field label="Approved by">
            <Text>
              {grant.approvalDetails.name ?? grant.approvalDetails.email ?? "—"}
              {grant.approvalDetails.approvedTimestamp ? (
                <Text dimColor>
                  {" · " +
                    formatRelative(grant.approvalDetails.approvedTimestamp)}
                </Text>
              ) : null}
              {grant.approvalDetails.approvalSource ? (
                <Text dimColor>
                  {" · via " + grant.approvalDetails.approvalSource}
                </Text>
              ) : null}
            </Text>
          </Field>
        ) : null}
      </Box>

      <DisplayRowsSection rows={visibleRows} />
      <HistorySection history={history} currentStatus={grant.status} />

      {onRelinquish && !canRelinquish ? (
        <Box marginTop={1}>
          <Text dimColor italic>
            Relinquish is only available while access is active (status
            DONE_NOTIFIED).
          </Text>
        </Box>
      ) : null}
      {pollWarning ? (
        <Box marginTop={1}>
          <Text dimColor>(refresh: {pollWarning})</Text>
        </Box>
      ) : null}
      <Box flexDirection="column" marginTop={1}>
        {actions.map((a, i) => (
          <ActionRow
            key={a}
            label={a === "relinquish" ? "Relinquish" : (backLabel ?? "Back")}
            kind={a}
            focused={i === actionIdx}
          />
        ))}
      </Box>
      <Box marginTop={1}>
        <Text dimColor>↑/↓ navigate · Enter to select · q/Esc back</Text>
      </Box>
    </Box>
  );
};

const DisplayRowsSection: React.FC<{ rows: GrantDisplayRow[] }> = ({
  rows,
}) => {
  if (rows.length === 0) return null;
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text color="gray" bold>
        DETAILS
      </Text>
      {rows.map((r, i) => (
        <Box key={`${r.label}-${i}`}>
          <Box width={24}>
            <Text dimColor>{r.label}</Text>
          </Box>
          <Box flexGrow={1}>
            <Text>{r.content}</Text>
          </Box>
        </Box>
      ))}
    </Box>
  );
};

const HistorySection: React.FC<{
  history: GrantHistoryEntry[];
  currentStatus: string;
}> = ({ history, currentStatus }) => {
  if (history.length === 0) return null;
  const terminal = isTerminalStatus(currentStatus);
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text color="gray" bold>
        HISTORY
      </Text>
      {history.map((entry, i) => {
        const isLast = i === history.length - 1;
        const info = statusInfo(entry.status);
        return (
          <Box key={`${entry.status}-${entry.timestamp}-${i}`}>
            <Box width={2}>
              <Text color={info.color}>{isLast ? "●" : "·"}</Text>
            </Box>
            <Box width={22}>
              <Text>{entry.label}</Text>
            </Box>
            <Text dimColor>
              {formatTimestamp(entry.timestamp)} ·{" "}
              {formatRelative(entry.timestamp)}
            </Text>
          </Box>
        );
      })}
      {!terminal ? (
        <Box>
          <Box width={2}>
            <Text dimColor>○</Text>
          </Box>
          <Text dimColor>
            <Spinner type="dots" /> Polling…
          </Text>
        </Box>
      ) : null}
    </Box>
  );
};

const ActionRow: React.FC<{
  label: string;
  kind: RequestDetailsAction;
  focused: boolean;
}> = ({ label, kind, focused }) => {
  const color = focused
    ? kind === "relinquish"
      ? "yellow"
      : "cyan"
    : undefined;
  return (
    <Box>
      <Box width={2}>
        <Text color="cyan" bold>
          {focused ? "❯" : " "}
        </Text>
      </Box>
      <Text color={color} bold={focused}>
        [ {label} ]
      </Text>
    </Box>
  );
};

const Field: React.FC<{
  label: string;
  children: React.ReactNode;
}> = ({ label, children }) => (
  <Box>
    <Box width={14}>
      <Text color="gray">{label}</Text>
    </Box>
    <Box flexGrow={1}>
      <Text>{children}</Text>
    </Box>
  </Box>
);

const ErrorScreen: React.FC<{ error: string; onBack: () => void }> = ({
  error,
  onBack,
}) => {
  useInput((_input, key) => {
    if (key.return || key.escape) onBack();
  });
  return (
    <Box flexDirection="column" paddingX={1}>
      <Text color="red">Error: {error}</Text>
      <Text dimColor>Press Enter or Esc to go back.</Text>
    </Box>
  );
};
