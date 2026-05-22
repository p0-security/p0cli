/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { MyGrant, fetchMyGrants, relinquishGrant } from "../drivers/api.js";
import { Authn } from "../types/identity.js";
import { RequestDetails } from "./RequestDetails.js";
import {
  describeGrant,
  formatExpiry,
  formatRelative,
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

const PAGE_SIZE = 8;

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
        <RequestDetails
          authn={authn}
          requestId={view.grantId}
          debug={debug}
          onBack={() => {
            setView({ kind: "list" });
            void reloadList();
          }}
          onRelinquish={(g) => setView({ kind: "confirming", grant: g })}
          backLabel="Back to list"
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
