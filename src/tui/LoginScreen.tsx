/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Box, Text, useInput } from "ink";
import TextInput from "ink-text-input";
import React, { useState } from "react";

type LoginScreenProps = {
  defaultOrg?: string;
  /** Optional banner (e.g. "Your session expired", "Login failed: …"). */
  message?: string;
  /**
   * Called when the user submits an org slug. The parent unmounts the
   * TUI and runs the OIDC browser flow; on completion, the TUI is
   * re-mounted with a refreshed session.
   */
  onSubmit: (orgSlug: string) => void;
  /** Called when the user presses Esc/Ctrl+C without submitting. */
  onCancel: () => void;
};

/**
 * Single-field "what's your org slug?" form, then hands off to the
 * existing `login` command (which opens a browser). Pre-fills from
 * `P0_ORG` / previous identity when available.
 */
export const LoginScreen: React.FC<LoginScreenProps> = ({
  defaultOrg,
  message,
  onSubmit,
  onCancel,
}) => {
  const [value, setValue] = useState<string>(defaultOrg ?? "");

  useInput((_input, key) => {
    if (key.escape) onCancel();
  });

  const handleSubmit = (raw: string) => {
    const trimmed = raw.trim();
    if (!trimmed) return;
    onSubmit(trimmed);
  };

  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold>Log in</Text>
      {message ? (
        <Box marginTop={1}>
          <Text color="yellow">{message}</Text>
        </Box>
      ) : null}
      <Box marginTop={1} flexDirection="column">
        <Text dimColor>
          Enter your P0 organization slug. A browser window will open to
          complete authentication.
        </Text>
        {defaultOrg ? (
          <Text dimColor>
            Default from {process.env.P0_ORG ? "P0_ORG" : "previous session"}:{" "}
            {defaultOrg}
          </Text>
        ) : null}
      </Box>
      <Box marginTop={1}>
        <Box width={14}>
          <Text color="gray">Organization</Text>
        </Box>
        <Box flexGrow={1}>
          <Text>{"> "}</Text>
          <TextInput
            value={value}
            onChange={setValue}
            onSubmit={handleSubmit}
            placeholder={defaultOrg ?? "your-org-slug"}
          />
        </Box>
      </Box>
      <Box marginTop={1}>
        <Text dimColor>Enter to continue · Esc to cancel</Text>
      </Box>
    </Box>
  );
};
