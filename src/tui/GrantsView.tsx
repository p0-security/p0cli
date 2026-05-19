/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  MyGrant,
  fetchMyGrant,
  fetchMyGrants,
  relinquishGrant,
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
import React, { useCallback, useEffect, useState } from "react";

type GrantsViewProps = {
  authn: Authn;
  debug?: boolean;
  onBack: () => void;
};

type View =
  | { kind: "confirming"; grant: MyGrant }
  | { kind: "details"; grantId: string }
  | { kind: "list" }
  | { kind: "relinquish-error"; grant: MyGrant; error: string }
  | { kind: "relinquished"; grant: MyGrant }
  | { kind: "relinquishing"; grant: MyGrant };

type ListState =
  | { kind: "error"; error: string }
  | { kind: "loading" }
  | { kind: "ready"; grants: MyGrant[] };

const RELINQUISHABLE_STATUS = "DONE_NOTIFIED";
const PAGE_SIZE = 8;
const DETAIL_POLL_INTERVAL_MS = 3000;

export const GrantsView: React.FC<GrantsViewProps> = ({
  authn,
  debug,
  onBack,
}) => {
  const [list, setList] = useState<ListState>({ kind: "loading" });
  const [view, setView] = useState<View>({ kind: "list" });

  const reloadList = useCallback(async () => {
    setList({ kind: "loading" });
    try {
      const grants = await fetchMyGrants(authn, debug);
      setList({ kind: "ready", grants });
    } catch (err) {
      setList({
        kind: "error",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }, [authn, debug]);

  useEffect(() => {
    void reloadList();
  }, [reloadList]);

  if (list.kind === "loading") {
    return (
      <Box paddingX={1}>
        <Text>
          <Spinner type="dots" /> Loading your access…
        </Text>
      </Box>
    );
  }

  if (list.kind === "error") {
    return <ErrorScreen error={list.error} onBack={onBack} />;
  }

  switch (view.kind) {
    case "list":
      return (
        <ListScreen
          grants={list.grants}
          onPick={(g) => setView({ kind: "details", grantId: g.requestId })}
          onBack={onBack}
        />
      );
    case "details":
      return (
        <DetailsScreen
          authn={authn}
          requestId={view.grantId}
          debug={debug}
          onBack={() => {
            setView({ kind: "list" });
            void reloadList();
          }}
          onRelinquish={(g) => setView({ kind: "confirming", grant: g })}
        />
      );
    case "confirming":
      return (
        <ConfirmScreen
          grant={view.grant}
          onCancel={() =>
            setView({ kind: "details", grantId: view.grant.requestId })
          }
          onConfirm={() => {
            const { grant } = view;
            setView({ kind: "relinquishing", grant });
            void relinquishGrant(authn, grant.requestId, debug)
              .then(() => setView({ kind: "relinquished", grant }))
              .catch((err: unknown) =>
                setView({
                  kind: "relinquish-error",
                  grant,
                  error: err instanceof Error ? err.message : String(err),
                })
              );
          }}
        />
      );
    case "relinquishing":
      return (
        <Box paddingX={1}>
          <Text>
            <Spinner type="dots" /> Relinquishing {describeGrant(view.grant)}…
          </Text>
        </Box>
      );
    case "relinquished":
      return (
        <RelinquishedScreen
          grant={view.grant}
          onContinue={() => {
            setView({ kind: "list" });
            void reloadList();
          }}
        />
      );
    case "relinquish-error":
      return (
        <RelinquishErrorScreen
          grant={view.grant}
          error={view.error}
          onRetry={() => setView({ kind: "confirming", grant: view.grant })}
          onBack={() =>
            setView({ kind: "details", grantId: view.grant.requestId })
          }
        />
      );
  }
};

const ListScreen: React.FC<{
  grants: MyGrant[];
  onPick: (g: MyGrant) => void;
  onBack: () => void;
}> = ({ grants, onPick, onBack }) => {
  const [idx, setIdx] = useState(0);
  const totalPages = Math.max(1, Math.ceil(grants.length / PAGE_SIZE));
  const page = Math.floor(idx / PAGE_SIZE);
  const start = page * PAGE_SIZE;
  const end = Math.min(start + PAGE_SIZE, grants.length);
  const pageGrants = grants.slice(start, end);

  useInput((input, key) => {
    if (grants.length === 0) {
      if (key.escape || input === "q" || key.return) onBack();
      return;
    }
    if (key.upArrow || input === "k") {
      setIdx((i) => (i + grants.length - 1) % grants.length);
    } else if (key.downArrow || input === "j") {
      setIdx((i) => (i + 1) % grants.length);
    } else if (
      key.pageDown ||
      input === "n" ||
      (key.rightArrow && totalPages > 1)
    ) {
      setIdx((i) => Math.min(grants.length - 1, i + PAGE_SIZE));
    } else if (
      key.pageUp ||
      input === "p" ||
      (key.leftArrow && totalPages > 1)
    ) {
      setIdx((i) => Math.max(0, i - PAGE_SIZE));
    } else if (key.return) {
      const g = grants[idx];
      if (g) onPick(g);
    } else if (key.escape || input === "q") {
      onBack();
    }
  });

  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold>My access</Text>
      <Text dimColor>
        {grants.length === 0
          ? "You currently have no open access requests."
          : totalPages > 1
            ? "↑/↓ navigate · n/p (or ←/→) page · Enter view details · q/Esc back"
            : "↑/↓ navigate · Enter view details · q/Esc back"}
      </Text>
      <Box flexDirection="column" marginTop={1}>
        {pageGrants.map((g, i) => (
          <GrantListRow
            key={g.requestId}
            grant={g}
            focused={start + i === idx}
          />
        ))}
      </Box>
      {totalPages > 1 ? (
        <Box marginTop={1}>
          <Text dimColor>
            Page {page + 1} of {totalPages} · showing {start + 1}–{end} of{" "}
            {grants.length}
          </Text>
        </Box>
      ) : null}
    </Box>
  );
};

const GrantListRow: React.FC<{
  grant: MyGrant;
  focused: boolean;
}> = ({ grant, focused }) => {
  const info = statusInfo(grant.status);
  return (
    <Box flexDirection="column">
      <Box>
        <Box width={2}>
          <Text color="cyan" bold>
            {focused ? "❯" : " "}
          </Text>
        </Box>
        <Text bold={focused} color={focused ? "cyan" : undefined}>
          {describeGrant(grant)}
        </Text>
      </Box>
      <Box marginLeft={2}>
        <Text color={info.color}>● {info.label}</Text>
        <Text dimColor>
          {" · "}
          {formatExpiry(grant)}
          {grant.duration ? ` · ${grant.duration}` : ""}
          {" · requested "}
          {formatRelative(grant.requestedTimestamp)}
        </Text>
      </Box>
      {grant.reason ? (
        <Box marginLeft={2}>
          <Text dimColor italic>
            "{truncate(grant.reason, 80)}"
          </Text>
        </Box>
      ) : null}
    </Box>
  );
};

const truncate = (s: string, max: number): string =>
  s.length <= max ? s : s.slice(0, max - 1) + "…";

type DetailsState =
  | { kind: "error"; error: string }
  | { kind: "loading" }
  | { kind: "ready"; grant: MyGrant };

const DetailsScreen: React.FC<{
  authn: Authn;
  requestId: string;
  debug?: boolean;
  onBack: () => void;
  onRelinquish: (g: MyGrant) => void;
}> = ({ authn, requestId, debug, onBack, onRelinquish }) => {
  const [state, setState] = useState<DetailsState>({ kind: "loading" });
  const [pollWarning, setPollWarning] = useState<string | null>(null);

  // Self-contained polling. Cancels on unmount AND stops polling when the
  // status reaches a terminal state (no more transitions possible).
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
        // First fetch failure → show error screen. Subsequent failures only
        // mark a refresh warning so the user can keep seeing the last data.
        setState((prev) =>
          prev.kind === "loading" ? { kind: "error", error: message } : prev
        );
        setPollWarning(message);
      }
      timer = setTimeout(() => void tick(), DETAIL_POLL_INTERVAL_MS);
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
          <Spinner type="dots" /> Loading grant…
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
    />
  );
};

const DetailsContent: React.FC<{
  grant: MyGrant;
  pollWarning: string | null;
  onBack: () => void;
  onRelinquish: (g: MyGrant) => void;
}> = ({ grant, pollWarning, onBack, onRelinquish }) => {
  const canRelinquish = grant.status === RELINQUISHABLE_STATUS;
  const actions: Array<"back" | "relinquish"> = canRelinquish
    ? ["relinquish", "back"]
    : ["back"];
  // Reset focus when the action set shrinks (e.g., after relinquish the
  // "relinquish" entry disappears).
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
      if (a === "relinquish") onRelinquish(grant);
      else if (a === "back") onBack();
    } else if (key.escape || input === "q") {
      onBack();
    }
  });

  const info = statusInfo(grant.status);
  const permissionEntries = flattenObject(grant.permission);
  const delegationEntries = flattenObject(grant.delegation);

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

      <KeyValueSection title="PERMISSION" entries={permissionEntries} />
      <KeyValueSection title="DELEGATION" entries={delegationEntries} />

      {!canRelinquish ? (
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
            label={a === "relinquish" ? "Relinquish" : "Back"}
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

const ActionRow: React.FC<{
  label: string;
  kind: "back" | "relinquish";
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

const KeyValueSection: React.FC<{
  title: string;
  entries: Array<{ key: string; value: string }>;
}> = ({ title, entries }) => {
  if (entries.length === 0) return null;
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text color="gray" bold>
        {title}
      </Text>
      {entries.map((e) => (
        <KeyValueRow key={e.key} entry={e} />
      ))}
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

const KeyValueRow: React.FC<{
  entry: { key: string; value: string };
}> = ({ entry }) => (
  <Box>
    <Box width={2}>
      <Text> </Text>
    </Box>
    <Box width={24}>
      <Text dimColor>{entry.key}</Text>
    </Box>
    <Box flexGrow={1}>
      <Text>{entry.value}</Text>
    </Box>
  </Box>
);

const ConfirmScreen: React.FC<{
  grant: MyGrant;
  onConfirm: () => void;
  onCancel: () => void;
}> = ({ grant, onConfirm, onCancel }) => {
  useInput((input, key) => {
    if (input === "y") onConfirm();
    else if (input === "n" || key.escape) onCancel();
  });

  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold color="yellow">
        Relinquish this access?
      </Text>
      <Box marginTop={1}>
        <Text>{describeGrant(grant)}</Text>
      </Box>
      <Box marginTop={1}>
        <Text dimColor>y to confirm · n or Esc to cancel</Text>
      </Box>
    </Box>
  );
};

const RelinquishedScreen: React.FC<{
  grant: MyGrant;
  onContinue: () => void;
}> = ({ grant, onContinue }) => {
  useInput((_input, key) => {
    if (key.return || key.escape) onContinue();
  });
  return (
    <Box flexDirection="column" paddingX={1}>
      <Text color="green" bold>
        ✓ Relinquished {describeGrant(grant)}
      </Text>
      <Text dimColor>Press Enter or Esc to return to the list.</Text>
    </Box>
  );
};

const RelinquishErrorScreen: React.FC<{
  grant: MyGrant;
  error: string;
  onRetry: () => void;
  onBack: () => void;
}> = ({ grant, error, onRetry, onBack }) => {
  useInput((input, key) => {
    if (input === "r") onRetry();
    else if (key.return || key.escape || input === "q") onBack();
  });
  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold color="red">
        ✗ Could not relinquish {describeGrant(grant)}
      </Text>
      <Box marginTop={1}>
        <Text color="red">{error}</Text>
      </Box>
      <Box marginTop={1}>
        <Text dimColor>r to retry · Enter/Esc to go back</Text>
      </Box>
    </Box>
  );
};

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

const flattenObject = (
  obj: Record<string, unknown>,
  prefix = ""
): Array<{ key: string; value: string }> => {
  const out: Array<{ key: string; value: string }> = [];
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      out.push(...flattenObject(v as Record<string, unknown>, key));
    } else {
      out.push({ key, value: formatScalar(v) });
    }
  }
  return out;
};

const formatScalar = (v: unknown): string => {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
};
