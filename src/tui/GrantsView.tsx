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
  debug?: boolean;
  onBack: () => void;
};

type View =
  | { kind: "confirming"; grant: MyGrant }
  | { kind: "details"; grant: MyGrant }
  | { kind: "list" }
  | { kind: "relinquished"; grant: MyGrant }
  | { kind: "relinquishing"; grant: MyGrant };

type ListState =
  | { kind: "error"; error: string }
  | { kind: "loading" }
  | { kind: "ready"; grants: MyGrant[] };

const RELINQUISHABLE_STATUS = "DONE_NOTIFIED";

const STATUS_LABEL: Record<string, { color: string; text: string }> = {
  APPROVED: { color: "cyan", text: "Approved — provisioning" },
  APPROVED_NOTIFIED: { color: "cyan", text: "Approved — provisioning" },
  DONE: { color: "green", text: "Active" },
  DONE_NOTIFIED: { color: "green", text: "Active" },
  ERRORED: { color: "red", text: "Errored" },
  EXPIRY_SUBMITTED: { color: "yellow", text: "Expiring" },
  NEW: { color: "yellow", text: "Pending approval" },
  PENDING_APPROVAL: { color: "yellow", text: "Pending approval" },
  PENDING_APPROVAL_ESCALATED: {
    color: "yellow",
    text: "Pending approval (escalated)",
  },
  REVOKE_SUBMITTED: { color: "yellow", text: "Revoking" },
  STAGED: { color: "cyan", text: "Provisioning" },
};

const statusBadge = (status: string): { color: string; text: string } =>
  STATUS_LABEL[status] ?? { color: "gray", text: status };

const describeGrant = (g: MyGrant): string => {
  const permSummary = renderPermissionSummary(g.permission);
  return permSummary
    ? `${g.type} · ${g.access} · ${permSummary}`
    : `${g.type} · ${g.access}`;
};

const renderPermissionSummary = (perm: Record<string, unknown>): string => {
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

const formatTimestamp = (ts: number | undefined): string => {
  if (!ts) return "—";
  return new Date(ts).toLocaleString();
};

export const GrantsView: React.FC<GrantsViewProps> = ({
  authn,
  debug,
  onBack,
}) => {
  const [list, setList] = useState<ListState>({ kind: "loading" });
  const [view, setView] = useState<View>({ kind: "list" });

  const load = useCallback(async () => {
    setList({ kind: "loading" });
    setView({ kind: "list" });
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
    void load();
  }, [load]);

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

  if (view.kind === "list") {
    return (
      <ListScreen
        grants={list.grants}
        onPick={(g) => setView({ kind: "details", grant: g })}
        onBack={onBack}
      />
    );
  }

  if (view.kind === "details") {
    return (
      <DetailsScreen
        grant={view.grant}
        onBack={() => setView({ kind: "list" })}
        onRelinquish={() => setView({ kind: "confirming", grant: view.grant })}
      />
    );
  }

  if (view.kind === "confirming") {
    return (
      <ConfirmScreen
        grant={view.grant}
        onCancel={() => setView({ kind: "details", grant: view.grant })}
        onConfirm={() => {
          const { grant } = view;
          setView({ kind: "relinquishing", grant });
          void (async () => {
            try {
              await relinquishGrant(authn, grant.requestId, debug);
              setView({ kind: "relinquished", grant });
            } catch (err) {
              setList({
                kind: "error",
                error: err instanceof Error ? err.message : String(err),
              });
            }
          })();
        }}
      />
    );
  }

  if (view.kind === "relinquishing") {
    return (
      <Box paddingX={1}>
        <Text>
          <Spinner type="dots" /> Relinquishing {describeGrant(view.grant)}…
        </Text>
      </Box>
    );
  }

  // relinquished
  return (
    <RelinquishedScreen grant={view.grant} onContinue={() => void load()} />
  );
};

const ListScreen: React.FC<{
  grants: MyGrant[];
  onPick: (g: MyGrant) => void;
  onBack: () => void;
}> = ({ grants, onPick, onBack }) => {
  const [idx, setIdx] = useState(0);

  useInput((input, key) => {
    if (grants.length === 0) {
      if (key.escape || input === "q" || key.return) onBack();
      return;
    }
    if (key.upArrow || input === "k") {
      setIdx((i) => (i + grants.length - 1) % grants.length);
    } else if (key.downArrow || input === "j") {
      setIdx((i) => (i + 1) % grants.length);
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
          : "↑/↓ navigate · Enter view details · q/Esc back"}
      </Text>
      <Box flexDirection="column" marginTop={1}>
        {grants.map((g, i) => {
          const focused = i === idx;
          const badge = statusBadge(g.status);
          return (
            <Box key={g.requestId} flexDirection="column">
              <Box>
                <Box width={2}>
                  <Text color="cyan" bold>
                    {focused ? "❯" : " "}
                  </Text>
                </Box>
                <Text bold={focused} color={focused ? "cyan" : undefined}>
                  {describeGrant(g)}
                </Text>
              </Box>
              <Box marginLeft={2}>
                <Text color={badge.color}>● {badge.text}</Text>
                <Text dimColor> · {formatExpiry(g)}</Text>
              </Box>
            </Box>
          );
        })}
      </Box>
    </Box>
  );
};

const DetailsScreen: React.FC<{
  grant: MyGrant;
  onBack: () => void;
  onRelinquish: () => void;
}> = ({ grant, onBack, onRelinquish }) => {
  const canRelinquish = grant.status === RELINQUISHABLE_STATUS;
  const actions: Array<"back" | "relinquish"> = canRelinquish
    ? ["relinquish", "back"]
    : ["back"];
  const [idx, setIdx] = useState(0);
  const badge = statusBadge(grant.status);

  useInput((input, key) => {
    if (key.upArrow || input === "k")
      setIdx((i) => (i + actions.length - 1) % actions.length);
    else if (key.downArrow || input === "j")
      setIdx((i) => (i + 1) % actions.length);
    else if (key.return) {
      const a = actions[idx];
      if (a === "relinquish") onRelinquish();
      else if (a === "back") onBack();
    } else if (key.escape || input === "q") onBack();
  });

  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold>{describeGrant(grant)}</Text>
      <Box marginTop={1} flexDirection="column">
        <Field label="Status">
          <Text color={badge.color}>● {badge.text} </Text>
          <Text dimColor>({grant.status})</Text>
        </Field>
        <Field label="Type">
          <Text>{grant.type}</Text>
        </Field>
        <Field label="Access">
          <Text>{grant.access}</Text>
        </Field>
        <Field label="Permission">
          <Text>
            {renderPermissionSummary(grant.permission) || "(see backend)"}
          </Text>
        </Field>
        <Field label="Requestor">
          <Text>{grant.requestor}</Text>
        </Field>
        <Field label="Principal">
          <Text>{grant.principal}</Text>
        </Field>
        <Field label="Requested">
          <Text>{formatTimestamp(grant.requestedTimestamp)}</Text>
        </Field>
        <Field label="Granted">
          <Text>{formatTimestamp(grant.grantTimestamp)}</Text>
        </Field>
        <Field label="Expires">
          <Text>
            {formatTimestamp(grant.expiryTimestamp)}
            {grant.expiryTimestamp ? (
              <Text dimColor>{` · ${formatExpiry(grant)}`}</Text>
            ) : null}
          </Text>
        </Field>
        {grant.reason ? (
          <Field label="Reason">
            <Text>{grant.reason}</Text>
          </Field>
        ) : null}
      </Box>
      {!canRelinquish ? (
        <Box marginTop={1}>
          <Text dimColor italic>
            Relinquish is only available while access is active (status
            DONE_NOTIFIED).
          </Text>
        </Box>
      ) : null}
      <Box flexDirection="column" marginTop={1}>
        {actions.map((a, i) => {
          const focused = i === idx;
          const color = focused
            ? a === "relinquish"
              ? "yellow"
              : "cyan"
            : undefined;
          const label = a === "relinquish" ? "Relinquish" : "Back";
          return (
            <Box key={a}>
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
        })}
      </Box>
      <Box marginTop={1}>
        <Text dimColor>↑/↓ navigate · Enter to select · q/Esc back</Text>
      </Box>
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
      <Text dimColor>Press Enter or Esc to refresh the list.</Text>
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
