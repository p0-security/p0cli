/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Authn } from "../types/identity.js";
import { GrantsView } from "./GrantsView.js";
import { RequestForm } from "./RequestForm.js";
import { TuiEntryFlow } from "./index.js";
import { Box, Text, useApp, useInput } from "ink";
import React, { useCallback, useState } from "react";

type AppProps = {
  authn: Authn;
  entry: TuiEntryFlow;
  debug?: boolean;
  onExit: (exitCode: number, info?: { submittedRequestIds?: string[] }) => void;
};

type Screen =
  | { kind: "granted" }
  | { kind: "menu" }
  | { kind: "relinquish" }
  | { kind: "request" };

const initialScreen = (entry: TuiEntryFlow): Screen =>
  entry === "request" ? { kind: "request" } : { kind: "menu" };

export const App: React.FC<AppProps> = ({ authn, entry, debug, onExit }) => {
  const { exit } = useApp();
  const [screen, setScreen] = useState<Screen>(initialScreen(entry));

  const handleExit = useCallback(
    (code: number, info?: { submittedRequestIds?: string[] }) => {
      exit();
      onExit(code, info);
    },
    [exit, onExit]
  );

  useInput((input, key) => {
    if (key.ctrl && input === "c") handleExit(130);
  });

  switch (screen.kind) {
    case "menu":
      return <MainMenu onPick={setScreen} onQuit={() => handleExit(0)} />;
    case "request":
      return (
        <RequestForm
          authn={authn}
          debug={debug}
          onCancel={() => {
            // From bare `p0 request` we exit; from the menu we go back.
            if (entry === "request") handleExit(0);
            else setScreen({ kind: "menu" });
          }}
          onSubmitted={(ids) => handleExit(0, { submittedRequestIds: ids })}
        />
      );
    case "granted":
      return (
        <GrantsView
          authn={authn}
          enableRelinquish={false}
          debug={debug}
          onBack={() => setScreen({ kind: "menu" })}
        />
      );
    case "relinquish":
      return (
        <GrantsView
          authn={authn}
          enableRelinquish={true}
          debug={debug}
          onBack={() => setScreen({ kind: "menu" })}
        />
      );
  }
};

type MainMenuProps = {
  onPick: (screen: Screen) => void;
  onQuit: () => void;
};

const MENU_ITEMS: Array<{ label: string; screen: Screen | "quit" }> = [
  { label: "Request access", screen: { kind: "request" } },
  { label: "View granted access", screen: { kind: "granted" } },
  { label: "Relinquish access", screen: { kind: "relinquish" } },
  { label: "Quit", screen: "quit" },
];

const MainMenu: React.FC<MainMenuProps> = ({ onPick, onQuit }) => {
  const [index, setIndex] = useState(0);

  useInput((input, key) => {
    if (key.upArrow || input === "k") {
      setIndex((i) => (i + MENU_ITEMS.length - 1) % MENU_ITEMS.length);
    } else if (key.downArrow || input === "j") {
      setIndex((i) => (i + 1) % MENU_ITEMS.length);
    } else if (key.return) {
      const item = MENU_ITEMS[index];
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
      <Box flexDirection="column" marginTop={1}>
        {MENU_ITEMS.map((item, i) => {
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
