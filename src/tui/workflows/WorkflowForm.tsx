/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Authn } from "../../types/identity.js";
import { useDebouncedValue } from "../hooks/useDebouncedValue.js";
import { WORKFLOWS, findWorkflow } from "./catalog.js";
import { Suggestion, fetchWorkflowSuggestions } from "./lister.js";
import { buildPreview } from "./preview.js";
import { WorkflowField, WorkflowSpec, WorkflowValues } from "./types.js";
import { Box, Text, useInput } from "ink";
import Spinner from "ink-spinner";
import TextInput from "ink-text-input";
import React, { useEffect, useMemo, useRef, useState } from "react";

type Props = {
  authn: Authn;
  debug?: boolean;
  onSubmit: (spec: WorkflowSpec, values: WorkflowValues) => void;
  onCancel: () => void;
};

type Mode = { fieldKey: string; kind: "edit" } | { kind: "navigate" };

type Action = "cancel" | "submit";

// Mirrors RequestForm's constants so labels, indicators, and option lists
// line up vertically when a user switches between the two forms.
const LABEL_WIDTH = 26;
const SUGGESTION_DEBOUNCE_MS = 200;
const DYNAMIC_RESULTS_DISPLAY_LIMIT = 8;
const NAV_HINT =
  "↑/↓ navigate  •  Enter to edit  •  Tab next  •  Esc cancel  •  Ctrl+C quit";
const EDIT_HINT_TEXT =
  "Type to edit  •  Enter to commit  •  Esc to cancel edit";
const EDIT_HINT_TOGGLE =
  "Space toggles  •  Enter commits  •  Esc to cancel edit";
const EDIT_HINT_SELECT = "↑/↓ choose  •  Enter to select  •  Esc to cancel";
const EDIT_HINT_DYNAMIC =
  "Type to filter  •  ↑/↓ choose  •  Enter to select  •  Esc to cancel";
const EDIT_HINT_WORKFLOW = EDIT_HINT_SELECT;

/**
 * Workflow picker is a pseudo-field at the top of the form — it's the
 * thing every workflow has in common. Slotting it into the same
 * focusable-row model as the regular fields means navigation /
 * keybinds / appearance match the rest of the form for free.
 */
const WORKFLOW_FIELD_KEY = "__workflow";

type FocusItem =
  | { action: Action; kind: "action" }
  | { field: WorkflowField; kind: "field" }
  | { kind: "workflow" };

export const WorkflowForm: React.FC<Props> = ({
  authn,
  debug,
  onSubmit,
  onCancel,
}) => {
  const [workflowId, setWorkflowId] = useState<string>(WORKFLOWS[0]!.id);
  const [valuesByWorkflow, setValuesByWorkflow] = useState<
    Record<string, WorkflowValues>
  >({});
  const [focusIndex, setFocusIndex] = useState<number>(0);
  const [mode, setMode] = useState<Mode>({ kind: "navigate" });
  const [submitError, setSubmitError] = useState<string | null>(null);

  const spec = useMemo(() => findWorkflow(workflowId)!, [workflowId]);
  const values = valuesByWorkflow[workflowId] ?? {};

  const focusableItems: FocusItem[] = useMemo(
    () => [
      { kind: "workflow" },
      ...spec.fields.map<FocusItem>((field) => ({ kind: "field", field })),
      { kind: "action", action: "submit" },
      { kind: "action", action: "cancel" },
    ],
    [spec.fields]
  );

  // Keep focusIndex in bounds when the field set changes (workflow swap).
  useEffect(() => {
    if (focusIndex >= focusableItems.length && focusableItems.length > 0) {
      setFocusIndex(focusableItems.length - 1);
    }
  }, [focusableItems.length, focusIndex]);

  const setFieldValue = (key: string, value: WorkflowValues[string]) => {
    setValuesByWorkflow((prev) => ({
      ...prev,
      [workflowId]: { ...(prev[workflowId] ?? {}), [key]: value },
    }));
  };

  const advanceFocus = () => {
    setFocusIndex((i) =>
      focusableItems.length === 0
        ? 0
        : Math.min(i + 1, focusableItems.length - 1)
    );
  };

  const commitFieldValue = (key: string, value: WorkflowValues[string]) => {
    setFieldValue(key, value);
    setMode({ kind: "navigate" });
    advanceFocus();
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

  const trySubmit = () => {
    const err = validate();
    if (err) {
      setSubmitError(err);
      return;
    }
    setSubmitError(null);
    onSubmit(spec, values);
  };

  useInput((input, key) => {
    if (mode.kind !== "navigate") return;
    if (key.upArrow) {
      setFocusIndex((i) =>
        focusableItems.length === 0
          ? 0
          : (i + focusableItems.length - 1) % focusableItems.length
      );
      return;
    }
    if (key.downArrow || key.tab) {
      setFocusIndex((i) =>
        focusableItems.length === 0 ? 0 : (i + 1) % focusableItems.length
      );
      return;
    }
    if (key.escape || input === "q") {
      onCancel();
      return;
    }
    if (key.return) {
      const item = focusableItems[focusIndex];
      if (!item) return;
      if (item.kind === "action") {
        if (item.action === "submit") trySubmit();
        else onCancel();
        return;
      }
      if (item.kind === "workflow") {
        setMode({ kind: "edit", fieldKey: WORKFLOW_FIELD_KEY });
        return;
      }
      setMode({ kind: "edit", fieldKey: item.field.key });
    }
  });

  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold>Run a workflow</Text>
      {submitError ? (
        <Box marginTop={1}>
          <Text color="red">✗ {submitError}</Text>
        </Box>
      ) : null}
      <Box flexDirection="column" marginTop={1}>
        {focusableItems.map((item, i) => {
          const focused = i === focusIndex && mode.kind === "navigate";

          if (item.kind === "action") {
            return (
              <ActionRow
                key={`action-${item.action}`}
                action={item.action}
                focused={focused}
              />
            );
          }

          if (item.kind === "workflow") {
            const editing =
              mode.kind === "edit" && mode.fieldKey === WORKFLOW_FIELD_KEY;
            return (
              <WorkflowRow
                key="workflow"
                spec={spec}
                focused={focused}
                editing={editing}
                onCommit={(picked) => {
                  if (picked.id !== workflowId) {
                    setWorkflowId(picked.id);
                    setSubmitError(null);
                  }
                  setMode({ kind: "navigate" });
                  advanceFocus();
                }}
                onCancelEdit={() => setMode({ kind: "navigate" })}
              />
            );
          }

          const editing =
            mode.kind === "edit" && mode.fieldKey === item.field.key;
          return (
            <FieldRow
              key={item.field.key}
              authn={authn}
              debug={debug}
              field={item.field}
              value={values[item.field.key]}
              values={values}
              focused={focused}
              editing={editing}
              onCommit={(v) => commitFieldValue(item.field.key, v)}
              onCancelEdit={() => setMode({ kind: "navigate" })}
            />
          );
        })}
      </Box>

      <Box flexDirection="column" marginTop={1}>
        <Text color="gray" bold>
          PREVIEW
        </Text>
        <Text dimColor>$ {buildPreview(spec, values)}</Text>
      </Box>

      <Box marginTop={1}>
        <Text dimColor>{hintForMode(mode, spec)}</Text>
      </Box>
    </Box>
  );
};

const hintForMode = (mode: Mode, spec: WorkflowSpec): string => {
  if (mode.kind === "navigate") return NAV_HINT;
  if (mode.fieldKey === WORKFLOW_FIELD_KEY) return EDIT_HINT_WORKFLOW;
  const field = spec.fields.find((f) => f.key === mode.fieldKey);
  if (!field) return EDIT_HINT_TEXT;
  switch (field.kind) {
    case "select":
      return EDIT_HINT_SELECT;
    case "dynamic-select":
      return EDIT_HINT_DYNAMIC;
    case "toggle":
      return EDIT_HINT_TOGGLE;
    default:
      return EDIT_HINT_TEXT;
  }
};

// ---------------------------------------------------------------------------
// Rows (match RequestForm's BlockRow / ActionRow / BlockLabel patterns)
// ---------------------------------------------------------------------------

const ActionRow: React.FC<{ action: Action; focused: boolean }> = ({
  action,
  focused,
}) => {
  const isSubmit = action === "submit";
  return (
    <Box marginTop={1}>
      <Box width={2}>
        <Text color="cyan" bold>
          {focused ? "❯" : " "}
        </Text>
      </Box>
      <Text
        color={focused ? (isSubmit ? "green" : "yellow") : undefined}
        bold={focused}
      >
        [ {isSubmit ? "Submit" : "Cancel"} ]
      </Text>
    </Box>
  );
};

const FieldLabel: React.FC<{
  label: string;
  focused: boolean;
  required?: boolean;
}> = ({ label, focused, required }) => (
  <Text>
    <Text color={focused ? "cyan" : "gray"} bold={focused}>
      {label.toUpperCase()}
    </Text>
    {required ? <Text color="yellow"> *</Text> : null}
  </Text>
);

const WorkflowRow: React.FC<{
  spec: WorkflowSpec;
  focused: boolean;
  editing: boolean;
  onCommit: (picked: WorkflowSpec) => void;
  onCancelEdit: () => void;
}> = ({ spec, focused, editing, onCommit, onCancelEdit }) => {
  return (
    <Box flexDirection="column">
      <Box>
        <Box width={2}>
          <Text color="cyan" bold>
            {focused ? "❯" : " "}
          </Text>
        </Box>
        <Box width={LABEL_WIDTH}>
          <FieldLabel label="Workflow" focused={focused} required />
        </Box>
        <Box flexGrow={1}>
          {editing ? (
            <Text dimColor italic>
              ─ editing ─
            </Text>
          ) : (
            <Text>
              {spec.command.join(" ")}
              <Text dimColor> · {spec.description}</Text>
            </Text>
          )}
        </Box>
      </Box>
      {editing ? (
        <Box marginLeft={4} marginTop={0}>
          <WorkflowSelectEditor
            currentId={spec.id}
            onCommit={onCommit}
            onCancelEdit={onCancelEdit}
          />
        </Box>
      ) : null}
    </Box>
  );
};

type FieldRowProps = {
  authn: Authn;
  debug?: boolean;
  field: WorkflowField;
  value: WorkflowValues[string];
  values: WorkflowValues;
  focused: boolean;
  editing: boolean;
  onCommit: (value: WorkflowValues[string]) => void;
  onCancelEdit: () => void;
};

const FieldRow: React.FC<FieldRowProps> = (props) => {
  const { field, focused, editing } = props;
  const required = "required" in field && field.required === true;

  const inlineEditor =
    editing &&
    (field.kind === "text" ||
      field.kind === "passthrough" ||
      field.kind === "toggle");
  const expandedEditor =
    editing && (field.kind === "select" || field.kind === "dynamic-select");

  return (
    <Box flexDirection="column">
      <Box>
        <Box width={2}>
          <Text color="cyan" bold>
            {focused ? "❯" : " "}
          </Text>
        </Box>
        <Box width={LABEL_WIDTH}>
          <FieldLabel
            label={field.label}
            focused={focused}
            required={required}
          />
        </Box>
        <Box flexGrow={1}>
          {inlineEditor ? (
            <InlineEditor {...props} />
          ) : expandedEditor ? (
            <Text dimColor italic>
              ─ editing ─
            </Text>
          ) : (
            <FieldSummary {...props} />
          )}
        </Box>
      </Box>
      {expandedEditor ? (
        <Box marginLeft={4} marginTop={0}>
          <ExpandedEditor {...props} />
        </Box>
      ) : null}
      {field.help && !editing ? (
        <Box marginLeft={2 + LABEL_WIDTH}>
          <Text dimColor>{field.help}</Text>
        </Box>
      ) : null}
    </Box>
  );
};

const FieldSummary: React.FC<FieldRowProps> = ({ field, value }) => {
  if (field.kind === "toggle") {
    const on = value === true;
    return (
      <Text>
        <Text color={on ? "green" : undefined}>{on ? "[x]" : "[ ]"}</Text>
        {" " + field.label}
      </Text>
    );
  }
  if (field.kind === "select") {
    const opt = field.options.find((o) => o.value === value);
    if (!opt) {
      return (
        <Text dimColor italic>
          (not set)
        </Text>
      );
    }
    return <Text>{opt.label}</Text>;
  }
  if (field.kind === "dynamic-select") {
    const raw = typeof value === "string" ? value : "";
    if (!raw) {
      return (
        <Text dimColor italic>
          {field.placeholder ?? "(press Enter to search)"}
        </Text>
      );
    }
    return <Text>{raw}</Text>;
  }
  // text / passthrough
  const raw = typeof value === "string" ? value : "";
  if (!raw) {
    return (
      <Text dimColor italic>
        {"placeholder" in field && field.placeholder
          ? field.placeholder
          : "(empty)"}
      </Text>
    );
  }
  if ("sensitive" in field && field.sensitive) {
    return <Text>{"•".repeat(Math.min(raw.length, 8))}</Text>;
  }
  return <Text>{raw}</Text>;
};

// ---------------------------------------------------------------------------
// Editors (match RequestForm's TextEditor / ToggleEditor / SelectEditor patterns)
// ---------------------------------------------------------------------------

const InlineEditor: React.FC<FieldRowProps> = (props) => {
  const { field } = props;
  if (field.kind === "text" || field.kind === "passthrough") {
    return <TextFieldEditor {...props} />;
  }
  if (field.kind === "toggle") return <ToggleEditor {...props} />;
  return null;
};

const ExpandedEditor: React.FC<FieldRowProps> = (props) => {
  const { field } = props;
  if (field.kind === "select") return <StaticSelectEditor {...props} />;
  if (field.kind === "dynamic-select") {
    return <DynamicSelectEditor {...props} />;
  }
  return null;
};

const TextFieldEditor: React.FC<FieldRowProps> = ({
  field,
  value,
  onCommit,
  onCancelEdit,
}) => {
  const initial = typeof value === "string" ? value : "";
  const [draft, setDraft] = useState<string>(initial);

  useInput((_input, key) => {
    if (key.escape) onCancelEdit();
  });

  return (
    <Box>
      <Text color="cyan">{"> "}</Text>
      <TextInput
        value={draft}
        onChange={setDraft}
        onSubmit={() => onCommit(draft)}
        placeholder={"placeholder" in field ? field.placeholder : undefined}
      />
    </Box>
  );
};

const ToggleEditor: React.FC<FieldRowProps> = ({
  field,
  value,
  onCommit,
  onCancelEdit,
}) => {
  const initial = value === true;
  const [on, setOn] = useState<boolean>(initial);

  useInput((input, key) => {
    if (key.escape) {
      onCancelEdit();
      return;
    }
    if (key.return) {
      onCommit(on);
      return;
    }
    if (input === " ") setOn((v) => !v);
    if (key.leftArrow) setOn(false);
    if (key.rightArrow) setOn(true);
  });

  return (
    <Text>
      <Text color={on ? "green" : undefined}>{on ? "[x]" : "[ ]"}</Text>
      {" " + field.label}
    </Text>
  );
};

const StaticSelectEditor: React.FC<FieldRowProps> = ({
  field,
  value,
  onCommit,
  onCancelEdit,
}) => {
  if (field.kind !== "select") return null;
  const options = field.options;
  const initialIdx = Math.max(
    0,
    options.findIndex((o) => o.value === value)
  );
  const [idx, setIdx] = useState(initialIdx);

  useInput((_input, key) => {
    if (key.escape) {
      onCancelEdit();
      return;
    }
    if (key.upArrow) {
      setIdx((i) => (i + options.length - 1) % options.length);
      return;
    }
    if (key.downArrow) {
      setIdx((i) => (i + 1) % options.length);
      return;
    }
    if (key.return) {
      const opt = options[idx];
      if (opt) onCommit(opt.value);
    }
  });

  return <SelectMenu options={options} idx={idx} />;
};

/**
 * Matches RequestForm's OptionList visual: cyan `›` focus marker, dim
 * `+ N more` overflow footer for long lists.
 */
const SelectMenu: React.FC<{
  options: { label: string; value: string }[];
  idx: number;
  maxDisplay?: number;
  emptyMessage?: string;
}> = ({ options, idx, maxDisplay, emptyMessage }) => {
  if (options.length === 0) {
    return <Text dimColor>{emptyMessage ?? "(no options available)"}</Text>;
  }
  const display =
    maxDisplay !== undefined ? options.slice(0, maxDisplay) : options;
  const overflow =
    maxDisplay !== undefined && options.length > maxDisplay
      ? options.length - maxDisplay
      : 0;
  return (
    <Box flexDirection="column">
      {display.map((opt, i) => {
        const focused = i === idx;
        return (
          <Text key={`${opt.value}-${i}`} color={focused ? "cyan" : undefined}>
            <Text color="cyan">{focused ? "› " : "  "}</Text>
            {opt.label}
          </Text>
        );
      })}
      {overflow > 0 ? (
        <Text dimColor>(+ {overflow} more — narrow your search)</Text>
      ) : null}
    </Box>
  );
};

const DynamicSelectEditor: React.FC<FieldRowProps> = ({
  authn,
  debug,
  field,
  value,
  values,
  onCommit,
  onCancelEdit,
}) => {
  if (field.kind !== "dynamic-select") return null;

  const dependsOn = useMemo(
    () =>
      (field.lister.dependsOn ?? [])
        .map((d) => ({
          flag: d.flag,
          value:
            typeof values[d.field] === "string"
              ? (values[d.field] as string)
              : "",
        }))
        .filter((d) => d.value.length > 0),
    [field.lister.dependsOn, values]
  );

  // Serialized for stable effect deps (avoids re-fetching on every render
  // when the parent re-creates the array reference).
  const dependsOnKey = useMemo(() => JSON.stringify(dependsOn), [dependsOn]);

  const initialQuery = typeof value === "string" ? value : "";
  const [query, setQuery] = useState<string>(initialQuery);
  const debouncedQuery = useDebouncedValue(query, SUGGESTION_DEBOUNCE_MS);
  const [suggestions, setSuggestions] = useState<Suggestion[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [idx, setIdx] = useState<number>(0);
  const fetchSeqRef = useRef(0);

  useEffect(() => {
    const seq = ++fetchSeqRef.current;
    setLoading(true);
    void (async () => {
      try {
        const items = await fetchWorkflowSuggestions(
          authn,
          field.lister.argv,
          debouncedQuery,
          { debug, dependsOn }
        );
        if (seq !== fetchSeqRef.current) return;
        setSuggestions(items);
        setIdx(0);
      } finally {
        if (seq === fetchSeqRef.current) setLoading(false);
      }
    })();
    // dependsOnKey is the stable serialization; intentionally not listing
    // dependsOn itself.
  }, [authn, debug, debouncedQuery, field.lister.argv, dependsOnKey]);

  useInput((_input, key) => {
    if (key.escape) {
      onCancelEdit();
      return;
    }
    if (key.upArrow) {
      setIdx((i) =>
        suggestions.length === 0
          ? 0
          : (i + suggestions.length - 1) % suggestions.length
      );
      return;
    }
    if (key.downArrow) {
      setIdx((i) =>
        suggestions.length === 0 ? 0 : (i + 1) % suggestions.length
      );
      return;
    }
    if (key.return) {
      const picked = suggestions[idx];
      if (picked) {
        onCommit(picked.value);
        return;
      }
      if (field.allowFreeText && query.trim().length > 0) {
        onCommit(query.trim());
      }
    }
  });

  return (
    <Box flexDirection="column">
      <Box>
        <Text color="cyan">? </Text>
        <TextInput
          value={query}
          onChange={setQuery}
          placeholder={field.placeholder ?? "Type to search…"}
        />
        {loading ? (
          <Text dimColor>
            {"  "}
            <Spinner type="dots" />
          </Text>
        ) : null}
      </Box>
      <SelectMenu
        options={suggestions.map((s) => ({
          // Mirror p0 ls semantics: the user sees `key`, we commit `value`.
          // Append `value` dimly when it differs (e.g. instance id vs alias).
          label: s.key + (s.value && s.value !== s.key ? `  (${s.value})` : ""),
          value: s.value,
        }))}
        idx={idx}
        maxDisplay={DYNAMIC_RESULTS_DISPLAY_LIMIT}
        emptyMessage={
          loading
            ? " "
            : field.allowFreeText
              ? "(no matches — Enter to use the typed value)"
              : "(no matches)"
        }
      />
    </Box>
  );
};

/**
 * Picker for the workflow itself. Listed in the same `SelectMenu` layout
 * the field selects use, just with the workflow description appended
 * dimly to each option so users have context while choosing.
 */
const WorkflowSelectEditor: React.FC<{
  currentId: string;
  onCommit: (picked: WorkflowSpec) => void;
  onCancelEdit: () => void;
}> = ({ currentId, onCommit, onCancelEdit }) => {
  const initialIdx = Math.max(
    0,
    WORKFLOWS.findIndex((w) => w.id === currentId)
  );
  const [idx, setIdx] = useState(initialIdx);

  useInput((_input, key) => {
    if (key.escape) {
      onCancelEdit();
      return;
    }
    if (key.upArrow) {
      setIdx((i) => (i + WORKFLOWS.length - 1) % WORKFLOWS.length);
      return;
    }
    if (key.downArrow) {
      setIdx((i) => (i + 1) % WORKFLOWS.length);
      return;
    }
    if (key.return) {
      const picked = WORKFLOWS[idx];
      if (picked) onCommit(picked);
    }
  });

  return (
    <Box flexDirection="column">
      {WORKFLOWS.map((w, i) => {
        const focused = i === idx;
        return (
          <Text key={w.id} color={focused ? "cyan" : undefined}>
            <Text color="cyan">{focused ? "› " : "  "}</Text>
            {w.command.join(" ")}
            <Text dimColor> · {w.description}</Text>
          </Text>
        );
      })}
    </Box>
  );
};
