/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { GrantsView } from "./GrantsView.js";
import { LoginScreen } from "./LoginScreen.js";
import { RequestForm } from "./RequestForm.js";
import { RequestSubmittedView } from "./RequestSubmittedView.js";
import { TuiEntryFlow, TuiIntent } from "./index.js";
import { Session, formatSessionRemaining } from "./session.js";
import { WorkflowForm } from "./workflows/WorkflowForm.js";
import { Box, Text, useInput } from "ink";
import React, { useCallback, useState } from "react";

type AppProps = {
  session: Session;
  entry: TuiEntryFlow;
  debug?: boolean;
  onIntent: (intent: TuiIntent) => void;
};

type Screen =
  | { kind: "login" }
  | { kind: "logout-confirm" }
  | { kind: "menu" }
  | { kind: "my-access" }
  | { kind: "request" }
  | { kind: "submitted"; requestIds: string[] }
  | { kind: "workflow" };

const initialScreen = (entry: TuiEntryFlow, session: Session): Screen => {
  // A direct `p0 request` against a logged-out session can't do anything
  // useful — route to login first.
  if (session.kind === "logged-out") return { kind: "login" };
  return entry === "request" ? { kind: "request" } : { kind: "menu" };
};

export const App: React.FC<AppProps> = ({
  session,
  entry,
  debug,
  onIntent,
}) => {
  const [screen, setScreen] = useState<Screen>(() =>
    initialScreen(entry, session)
  );

  const exit = useCallback(
    (code: number) => onIntent({ kind: "exit", exitCode: code }),
    [onIntent]
  );

  // For sub-screens that should return to the main menu when dismissed
  // (via the menu entry) or exit (via direct `p0 request`).
  const backFromSubScreen = useCallback(() => {
    if (entry === "menu" || session.kind === "logged-out") {
      setScreen({ kind: "menu" });
    } else {
      exit(0);
    }
  }, [entry, exit, session.kind]);

  useInput((input, key) => {
    if (key.ctrl && input === "c") exit(130);
  });

  return (
    <Box flexDirection="column">
      <Header session={session} />
      <Content
        screen={screen}
        session={session}
        debug={debug}
        onPickScreen={setScreen}
        onIntent={onIntent}
        onBack={backFromSubScreen}
        onQuit={() => exit(0)}
      />
    </Box>
  );
};

const Content: React.FC<{
  screen: Screen;
  session: Session;
  debug?: boolean;
  onPickScreen: (s: Screen) => void;
  onIntent: (intent: TuiIntent) => void;
  onBack: () => void;
  onQuit: () => void;
}> = ({ screen, session, debug, onPickScreen, onIntent, onBack, onQuit }) => {
  switch (screen.kind) {
    case "menu":
      return (
        <MainMenu session={session} onPick={onPickScreen} onQuit={onQuit} />
      );
    case "login":
      return (
        <LoginScreen
          defaultOrg={
            session.kind === "logged-out" ? session.defaultOrg : undefined
          }
          message={session.kind === "logged-out" ? session.message : undefined}
          onSubmit={(orgSlug) => onIntent({ kind: "login", orgSlug })}
          onCancel={onQuit}
        />
      );
    case "logout-confirm":
      return (
        <LogoutConfirm
          session={session}
          onConfirm={() => onIntent({ kind: "logout" })}
          onCancel={() => onPickScreen({ kind: "menu" })}
        />
      );
    case "request":
      if (session.kind !== "logged-in") {
        // Defensive — menu shouldn't let this happen, but route gracefully.
        return (
          <NotLoggedIn message="You need to log in before you can request access." />
        );
      }
      return (
        <RequestForm
          authn={session.authn}
          debug={debug}
          onCancel={onBack}
          onSubmitted={(ids) =>
            onPickScreen({ kind: "submitted", requestIds: ids })
          }
        />
      );
    case "submitted":
      if (session.kind !== "logged-in") {
        return <NotLoggedIn message="Your session ended." />;
      }
      return (
        <RequestSubmittedView
          authn={session.authn}
          requestIds={screen.requestIds}
          debug={debug}
          onDismiss={onBack}
        />
      );
    case "my-access":
      if (session.kind !== "logged-in") {
        return (
          <NotLoggedIn message="You need to log in to view your access." />
        );
      }
      return <GrantsView authn={session.authn} debug={debug} onBack={onBack} />;
    case "workflow":
      if (session.kind !== "logged-in") {
        return (
          <NotLoggedIn message="You need to log in before you can run a workflow." />
        );
      }
      return (
        <WorkflowForm
          onSubmit={(spec, values) =>
            onIntent({ kind: "workflow", workflowId: spec.id, values })
          }
          onCancel={onBack}
        />
      );
  }
};

const Header: React.FC<{ session: Session }> = ({ session }) => {
  if (session.kind === "logged-in") {
    const remaining = formatSessionRemaining(session.expiresInSec);
    return (
      <Box paddingX={1} flexDirection="row">
        <Text bold>P0</Text>
        <Text dimColor> · </Text>
        <Text>{session.email ?? "(unknown user)"}</Text>
        <Text dimColor> · </Text>
        <Text color="cyan">{session.orgSlug}</Text>
        <Text dimColor> · session {remaining}</Text>
      </Box>
    );
  }
  return (
    <Box paddingX={1} flexDirection="row">
      <Text bold>P0</Text>
      <Text dimColor> · </Text>
      <Text color="yellow">not logged in</Text>
      {session.defaultOrg ? (
        <Text dimColor> · default org: {session.defaultOrg}</Text>
      ) : null}
    </Box>
  );
};

type MenuItem = { label: string; screen: Screen | "quit" };

const menuItemsFor = (session: Session): MenuItem[] => {
  if (session.kind === "logged-out") {
    return [
      { label: "Log in", screen: { kind: "login" } },
      { label: "Quit", screen: "quit" },
    ];
  }
  return [
    { label: "Request access", screen: { kind: "request" } },
    {
      label: "Run a workflow (ssh, kubeconfig, aws…)",
      screen: { kind: "workflow" },
    },
    { label: "My access (view / relinquish)", screen: { kind: "my-access" } },
    { label: "Log out", screen: { kind: "logout-confirm" } },
    { label: "Quit", screen: "quit" },
  ];
};

const MainMenu: React.FC<{
  session: Session;
  onPick: (screen: Screen) => void;
  onQuit: () => void;
}> = ({ session, onPick, onQuit }) => {
  const items = menuItemsFor(session);
  const [index, setIndex] = useState(0);

  useInput((input, key) => {
    if (key.upArrow || input === "k") {
      setIndex((i) => (i + items.length - 1) % items.length);
    } else if (key.downArrow || input === "j") {
      setIndex((i) => (i + 1) % items.length);
    } else if (key.return) {
      const item = items[index];
      if (!item) return;
      if (item.screen === "quit") onQuit();
      else onPick(item.screen);
    } else if (input === "q" || key.escape) {
      onQuit();
    }
  });

  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold>P0 Interactive</Text>
      <Text dimColor>↑/↓ navigate · Enter select · q/Esc quit</Text>
      {session.kind === "logged-out" ? (
        <Box marginTop={1}>
          <Text color="yellow">
            Log in to request access or view your existing grants.
          </Text>
        </Box>
      ) : null}
      <Box flexDirection="column" marginTop={1}>
        {items.map((item, i) => {
          const focused = i === index;
          return (
            <Text key={item.label} color={focused ? "cyan" : undefined}>
              {focused ? "❯ " : "  "}
              {item.label}
            </Text>
          );
        })}
      </Box>
    </Box>
  );
};

const LogoutConfirm: React.FC<{
  session: Session;
  onConfirm: () => void;
  onCancel: () => void;
}> = ({ session, onConfirm, onCancel }) => {
  useInput((input, key) => {
    if (input === "y") onConfirm();
    else if (input === "n" || key.escape) onCancel();
  });
  const target = session.kind === "logged-in" ? session.orgSlug : "this device";
  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold color="yellow">
        Log out of {target}?
      </Text>
      <Text dimColor>
        This clears the cached credentials on this device. You can log back in
        at any time.
      </Text>
      <Box marginTop={1}>
        <Text dimColor>y to confirm · n or Esc to cancel</Text>
      </Box>
    </Box>
  );
};

const NotLoggedIn: React.FC<{ message: string }> = ({ message }) => (
  <Box flexDirection="column" paddingX={1}>
    <Text color="yellow">{message}</Text>
    <Text dimColor>Press q/Esc to return to the main menu.</Text>
  </Box>
);
