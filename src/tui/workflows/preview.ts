/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { WorkflowField, WorkflowSpec, WorkflowValues } from "./types.js";

/**
 * Shell-quotes an argument value for display purposes only. The string
 * returned by this function is NEVER passed to a shell — it's only
 * shown to the user as the "what this would look like on the CLI"
 * preview. Workflow execution always uses array-style spawn so user
 * input never reaches a shell.
 */
const quoteArg = (raw: string): string => {
  if (raw.length === 0) return "''";
  // Bareword if it contains only POSIX-safe characters.
  if (/^[A-Za-z0-9_./:@%+,=-]+$/.test(raw)) return raw;
  // Single-quote and escape embedded single quotes the usual POSIX way.
  return `'${raw.replace(/'/g, `'\\''`)}'`;
};

const SENSITIVE_PLACEHOLDER = "'••••'";

/**
 * Builds a copy-pasteable `p0 ...` command equivalent to the form's
 * current values, for the live preview line above the action bar.
 *
 * Sensitive fields (marked via {@link WorkflowField.sensitive}) are
 * rendered as `••••` to avoid shoulder-surfing the value while the
 * user is typing.
 */
export const buildPreview = (
  spec: WorkflowSpec,
  values: WorkflowValues
): string => {
  const tokens: string[] = ["p0", ...spec.command];
  const positionals = spec.fields.filter(
    (f): f is Extract<WorkflowField, { positional?: boolean }> =>
      "positional" in f && f.positional === true
  );

  // Positionals first, in declaration order. Trailing optional
  // positionals are only included if filled in.
  let trailingEmpty = 0;
  const positionalRendered: string[] = [];
  for (const field of positionals) {
    const raw = values[field.key];
    const str = typeof raw === "string" ? raw : "";
    if (!str) {
      trailingEmpty++;
      continue;
    }
    if (trailingEmpty > 0) {
      // Required positionals can't be skipped — render placeholders.
      positionalRendered.push(...Array(trailingEmpty).fill("<...>"));
      trailingEmpty = 0;
    }
    positionalRendered.push(
      field.sensitive ? SENSITIVE_PLACEHOLDER : quoteArg(str)
    );
  }
  tokens.push(...positionalRendered);

  // Keyword args. Toggles render as bare `--flag` only when true.
  for (const field of spec.fields) {
    if ("positional" in field && field.positional) continue;
    if (field.kind === "passthrough") continue;
    const value = values[field.key];
    if (field.kind === "toggle") {
      if (value === true) tokens.push(`--${field.key}`);
      continue;
    }
    if (typeof value !== "string" || value.length === 0) continue;
    tokens.push(`--${field.key}`);
    tokens.push(
      "sensitive" in field && field.sensitive
        ? SENSITIVE_PLACEHOLDER
        : quoteArg(value)
    );
  }

  // Passthrough `-- ...` args (currently only SSH/SCP).
  const passthrough = spec.fields.find((f) => f.kind === "passthrough");
  if (passthrough) {
    const raw = values[passthrough.key];
    const parts = Array.isArray(raw)
      ? raw
      : typeof raw === "string"
        ? raw.split(/\s+/).filter(Boolean)
        : [];
    if (parts.length > 0) {
      tokens.push("--");
      tokens.push(...parts.map(quoteArg));
    }
  }

  return tokens.join(" ");
};

/**
 * Splits passthrough args into the array form spawn() expects. Only
 * whitespace splitting — no shell interpretation. If the user wants a
 * literal space in an argument they can use a quoted form in their
 * config, but inside the TUI we keep this simple.
 */
export const parsePassthrough = (raw: string | undefined): string[] => {
  if (!raw) return [];
  return raw.split(/\s+/).filter((s) => s.length > 0);
};
