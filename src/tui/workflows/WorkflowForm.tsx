/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { WORKFLOWS, findWorkflow } from "./catalog.js";
import { buildPreview } from "./preview.js";
import { WorkflowField, WorkflowSpec, WorkflowValues } from "./types.js";
import { Box, Text, useInput } from "ink";
import TextInput from "ink-text-input";
import React, { useMemo, useState } from "react";

type Props = {
  onSubmit: (spec: WorkflowSpec, values: WorkflowValues) => void;
  onCancel: () => void;
};

type Mode =
  | { kind: "edit-select"; fieldKey: string; index: number }
  | { kind: "edit-text"; fieldKey: string }
  | { kind: "edit-toggle"; fieldKey: string }
  | { kind: "edit-workflow" }
  | { kind: "navigate" };

const FIELD_LABEL_WIDTH = 22;
const NAV_HINT = "↑/↓ navigate · Enter to edit · s to submit · q/Esc cancel";

/**
 * Top-of-form workflow picker, followed by a dynamic set of fields for
 * the selected workflow. Submit calls back with the spec + collected
 * values; the parent runs the workflow.
 */
export const WorkflowForm: React.FC<Props> = ({ onSubmit, onCancel }) => {
  const [workflowId, setWorkflowId] = useState<string>(WORKFLOWS[0]!.id);
  const [valuesByWorkflow, setValuesByWorkflow] = useState<
    Record<string, WorkflowValues>
  >({});
  const [focus, setFocus] = useState<number>(0);
  const [mode, setMode] = useState<Mode>({ kind: "navigate" });
  const [error, setError] = useState<string | null>(null);

  const spec = useMemo(() => findWorkflow(workflowId)!, [workflowId]);
  const values = valuesByWorkflow[workflowId] ?? {};

  // Logical row count = workflow picker (row 0) + spec.fields.length
  const rowCount = 1 + spec.fields.length;

  const setFieldValue = (key: string, value: WorkflowValues[string]) => {
    setValuesByWorkflow((prev) => ({
      ...prev,
      [workflowId]: { ...(prev[workflowId] ?? {}), [key]: value },
    }));
  };

  const validate = (): string | null => {
    for (const field of spec.fields) {
      if (field.kind === "passthrough" || field.kind === "toggle") continue;
      if (!("required" in field) || !field.required) continue;
      const v = values[field.key];
      if (typeof v !== "string" || v.trim().length === 0) {
        return `"${field.label}" is required.`;
      }
    }
    return null;
  };

  useInput((input, key) => {
    if (mode.kind !== "navigate") return;
    if (key.upArrow || input === "k") {
      setFocus((i) => (i + rowCount - 1) % rowCount);
    } else if (key.downArrow || input === "j") {
      setFocus((i) => (i + 1) % rowCount);
    } else if (key.escape || input === "q") {
      onCancel();
    } else if (key.return) {
      if (focus === 0) {
        setMode({ kind: "edit-workflow" });
        return;
      }
      const field = spec.fields[focus - 1];
      if (!field) return;
      if (field.kind === "toggle") {
        setMode({ kind: "edit-toggle", fieldKey: field.key });
        return;
      }
      if (field.kind === "select") {
        const currentValue = values[field.key];
        const idx = Math.max(
          0,
          field.options.findIndex((o) => o.value === currentValue)
        );
        setMode({ kind: "edit-select", fieldKey: field.key, index: idx });
        return;
      }
      // text / passthrough — both use TextInput.
      setMode({ kind: "edit-text", fieldKey: field.key });
    } else if (input === "s") {
      const err = validate();
      if (err) {
        setError(err);
        return;
      }
      onSubmit(spec, values);
    }
  });

  // Edit-workflow handling: simple list arrow nav.
  const [workflowIdx, setWorkflowIdx] = useState<number>(() =>
    Math.max(
      0,
      WORKFLOWS.findIndex((w) => w.id === workflowId)
    )
  );
  useInput(
    (input, key) => {
      if (mode.kind !== "edit-workflow") return;
      if (key.upArrow || input === "k") {
        setWorkflowIdx((i) => (i + WORKFLOWS.length - 1) % WORKFLOWS.length);
      } else if (key.downArrow || input === "j") {
        setWorkflowIdx((i) => (i + 1) % WORKFLOWS.length);
      } else if (key.return) {
        const picked = WORKFLOWS[workflowIdx];
        if (picked) {
          setWorkflowId(picked.id);
          setFocus(0);
          setError(null);
        }
        setMode({ kind: "navigate" });
      } else if (key.escape) {
        setMode({ kind: "navigate" });
      }
    },
    { isActive: mode.kind === "edit-workflow" }
  );

  // Toggle edit: y/n/space then back to navigate.
  useInput(
    (input, key) => {
      if (mode.kind !== "edit-toggle") return;
      const fieldKey = mode.fieldKey;
      const current = values[fieldKey] === true;
      if (input === " " || key.return) {
        setFieldValue(fieldKey, !current);
        setMode({ kind: "navigate" });
      } else if (input === "y") {
        setFieldValue(fieldKey, true);
        setMode({ kind: "navigate" });
      } else if (input === "n") {
        setFieldValue(fieldKey, false);
        setMode({ kind: "navigate" });
      } else if (key.escape) {
        setMode({ kind: "navigate" });
      }
    },
    { isActive: mode.kind === "edit-toggle" }
  );

  // Select edit: arrow + Enter.
  const [selectIdx, setSelectIdx] = useState<number>(0);
  React.useEffect(() => {
    if (mode.kind === "edit-select") setSelectIdx(mode.index);
  }, [mode]);
  useInput(
    (input, key) => {
      if (mode.kind !== "edit-select") return;
      const field = spec.fields.find(
        (f): f is Extract<WorkflowField, { kind: "select" }> =>
          f.kind === "select" && f.key === mode.fieldKey
      );
      if (!field) return;
      if (key.upArrow || input === "k") {
        setSelectIdx(
          (i) => (i + field.options.length - 1) % field.options.length
        );
      } else if (key.downArrow || input === "j") {
        setSelectIdx((i) => (i + 1) % field.options.length);
      } else if (key.return) {
        const opt = field.options[selectIdx];
        if (opt) setFieldValue(field.key, opt.value);
        setMode({ kind: "navigate" });
      } else if (key.escape) {
        setMode({ kind: "navigate" });
      }
    },
    { isActive: mode.kind === "edit-select" }
  );

  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold>Run a workflow</Text>
      <Text dimColor>{NAV_HINT}</Text>

      <Box marginTop={1} flexDirection="column">
        <FormRow
          focused={focus === 0 && mode.kind === "navigate"}
          label="Workflow"
        >
          <Text>{spec.command.join(" ")}</Text>
          <Text dimColor> · {spec.description}</Text>
        </FormRow>

        {spec.fields.map((field, i) => {
          const rowFocused = focus === i + 1 && mode.kind === "navigate";
          const editingText =
            (mode.kind === "edit-text" && mode.fieldKey === field.key) ||
            (mode.kind === "edit-text" &&
              field.kind === "passthrough" &&
              mode.fieldKey === field.key);
          return (
            <FormRow
              key={field.key}
              focused={rowFocused}
              label={field.label}
              hint={field.help}
              required={"required" in field && field.required}
            >
              <FieldValue
                field={field}
                value={values[field.key]}
                editingText={editingText}
                onTextSubmit={(raw) => {
                  setFieldValue(field.key, raw);
                  setMode({ kind: "navigate" });
                }}
                onTextChange={(raw) => setFieldValue(field.key, raw)}
                onTextCancel={() => setMode({ kind: "navigate" })}
              />
            </FormRow>
          );
        })}
      </Box>

      {mode.kind === "edit-workflow" ? (
        <Box flexDirection="column" marginTop={1} paddingX={1}>
          <Text color="gray" bold>
            Pick a workflow
          </Text>
          {WORKFLOWS.map((w, i) => (
            <Text
              key={w.id}
              color={i === workflowIdx ? "cyan" : undefined}
              bold={i === workflowIdx}
            >
              {i === workflowIdx ? "❯ " : "  "}
              {w.command.join(" ")}
              <Text dimColor> · {w.description}</Text>
            </Text>
          ))}
          <Text dimColor>↑/↓ choose · Enter to select · Esc to cancel</Text>
        </Box>
      ) : null}

      {mode.kind === "edit-select"
        ? (() => {
            const field = spec.fields.find(
              (f): f is Extract<WorkflowField, { kind: "select" }> =>
                f.kind === "select" && f.key === mode.fieldKey
            );
            if (!field) return null;
            return (
              <Box flexDirection="column" marginTop={1} paddingX={1}>
                <Text color="gray" bold>
                  Pick {field.label}
                </Text>
                {field.options.map((opt, i) => (
                  <Text
                    key={opt.value}
                    color={i === selectIdx ? "cyan" : undefined}
                    bold={i === selectIdx}
                  >
                    {i === selectIdx ? "❯ " : "  "}
                    {opt.label}
                  </Text>
                ))}
                <Text dimColor>
                  ↑/↓ choose · Enter to select · Esc to cancel
                </Text>
              </Box>
            );
          })()
        : null}

      {mode.kind === "edit-toggle" ? (
        <Box marginTop={1}>
          <Text dimColor>Space/Enter to toggle · y / n · Esc to cancel</Text>
        </Box>
      ) : null}

      <Box marginTop={1} flexDirection="column">
        <Text color="gray" bold>
          PREVIEW
        </Text>
        <Text dimColor>$ {buildPreview(spec, values)}</Text>
      </Box>

      {error ? (
        <Box marginTop={1}>
          <Text color="red">{error}</Text>
        </Box>
      ) : null}

      <Box marginTop={1}>
        <Text dimColor>s to submit · q/Esc to cancel</Text>
      </Box>
    </Box>
  );
};

const FormRow: React.FC<{
  focused: boolean;
  label: string;
  hint?: string;
  required?: boolean;
  children: React.ReactNode;
}> = ({ focused, label, hint, required, children }) => (
  <Box flexDirection="column">
    <Box>
      <Box width={2}>
        <Text color="cyan" bold>
          {focused ? "❯" : " "}
        </Text>
      </Box>
      <Box width={FIELD_LABEL_WIDTH}>
        <Text color={focused ? "cyan" : "gray"}>
          {label}
          {required ? <Text color="red"> *</Text> : null}
        </Text>
      </Box>
      <Box flexGrow={1}>
        <Text>{children}</Text>
      </Box>
    </Box>
    {hint && focused ? (
      <Box marginLeft={FIELD_LABEL_WIDTH + 2}>
        <Text dimColor italic>
          {hint}
        </Text>
      </Box>
    ) : null}
  </Box>
);

const FieldValue: React.FC<{
  field: WorkflowField;
  value: WorkflowValues[string];
  editingText: boolean;
  onTextSubmit: (raw: string) => void;
  onTextChange: (raw: string) => void;
  onTextCancel: () => void;
}> = ({ field, value, editingText, onTextSubmit, onTextChange }) => {
  if (field.kind === "toggle") {
    return (
      <Text color={value === true ? "green" : undefined}>
        [{value === true ? "x" : " "}] {value === true ? "on" : "off"}
      </Text>
    );
  }
  if (field.kind === "select") {
    const opt = field.options.find((o) => o.value === value);
    if (opt) return <Text>{opt.label}</Text>;
    return <Text dimColor>(not set)</Text>;
  }
  // text / passthrough
  if (editingText) {
    const raw = typeof value === "string" ? value : "";
    return (
      <Text>
        {"> "}
        <TextInput
          value={raw}
          onChange={onTextChange}
          onSubmit={onTextSubmit}
          placeholder={"placeholder" in field ? field.placeholder : undefined}
        />
      </Text>
    );
  }
  const raw = typeof value === "string" ? value : "";
  if (raw === "") {
    return (
      <Text dimColor>
        {"placeholder" in field && field.placeholder
          ? field.placeholder
          : "(not set)"}
      </Text>
    );
  }
  if ("sensitive" in field && field.sensitive) {
    return <Text>{"•".repeat(Math.min(raw.length, 8))}</Text>;
  }
  return <Text>{raw}</Text>;
};
