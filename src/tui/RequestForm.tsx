/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  fetchRequestForm,
  fetchSuggestions,
  submitWebRequest,
} from "../drivers/api.js";
import { Authn } from "../types/identity.js";
import {
  RESOURCE_SELECTOR_BLOCK_ID,
  WebAction,
  WebBlock,
  WebDynamicSelectBlock,
  WebInputBlock,
  WebInputChoice,
  WebModalState,
  WebStaticSelectBlock,
  WebToggleBlock,
} from "../types/web-request.js";
import { useDebouncedValue } from "./hooks/useDebouncedValue.js";
import { Box, Text, useInput } from "ink";
import Spinner from "ink-spinner";
import TextInput from "ink-text-input";
import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

type RequestFormProps = {
  authn: Authn;
  debug?: boolean;
  /** Called with the request IDs returned by the server immediately after a
   *  successful submit; the parent transitions to the polling view. */
  onSubmitted: (requestIds: string[]) => void;
  /** Called when the user cancels before submit. */
  onCancel: () => void;
};

type FormState =
  | {
      kind: "ready";
      blocks: WebBlock[];
      actions: WebAction[];
      refreshing: boolean;
    }
  | { kind: "error"; error: string }
  | { kind: "loading" };

type Mode =
  | { kind: "edit"; blockId: string }
  | { kind: "navigate" }
  | { kind: "submitting" };

/** Width of the label column. Labels longer than this will wrap. */
const LABEL_WIDTH = 26;

const NAV_HINT =
  "↑/↓ navigate  •  Enter to edit  •  Tab next  •  Esc cancel  •  Ctrl+C quit";
const EDIT_HINT_TEXT =
  "Type to edit  •  Enter to commit  •  Esc to cancel edit";
const EDIT_HINT_SELECT_SINGLE =
  "↑/↓ choose  •  Enter to select  •  Esc to cancel";
const EDIT_HINT_SELECT_MULTI =
  "↑/↓ choose  •  Space to toggle  •  Enter to commit  •  Esc to cancel";

export const RequestForm: React.FC<RequestFormProps> = ({
  authn,
  debug,
  onSubmitted,
  onCancel,
}) => {
  const [values, setValues] = useState<WebModalState>({});
  const [state, setState] = useState<FormState>({ kind: "loading" });
  const [mode, setMode] = useState<Mode>({ kind: "navigate" });
  const [focusIndex, setFocusIndex] = useState(0);
  // Submit-time error surfaced as a banner above the form so the user can
  // fix the input and retry without losing what they typed.
  const [submitError, setSubmitError] = useState<string | null>(null);

  // Latest in-flight form fetch id; lets us discard stale responses.
  const fetchSeqRef = useRef(0);

  const refreshForm = useCallback(
    async (nextValues: WebModalState) => {
      const seq = ++fetchSeqRef.current;
      setState((prev) =>
        prev.kind === "ready"
          ? { ...prev, refreshing: true }
          : { kind: "loading" }
      );
      try {
        const res = await fetchRequestForm(authn, nextValues, debug);
        if (seq !== fetchSeqRef.current) return;
        if (!res.ok) {
          setState({ kind: "error", error: res.error });
          return;
        }

        // Auto-pick the resource if and only if there's exactly one option.
        // The block is also hidden from the focusable list in that case
        // (see `focusableItems` below). When there are multiple integrations
        // the user must pick one explicitly.
        const resourceBlock = res.blocks.find(
          (b) =>
            b.id === RESOURCE_SELECTOR_BLOCK_ID && b.type === "static-select"
        ) as WebStaticSelectBlock | undefined;
        if (
          !nextValues[RESOURCE_SELECTOR_BLOCK_ID] &&
          resourceBlock?.options?.length === 1
        ) {
          const firstResource = resourceBlock.options[0];
          if (firstResource) {
            const withResource = {
              ...nextValues,
              [RESOURCE_SELECTOR_BLOCK_ID]: firstResource.value,
            };
            setValues(withResource);
            // Re-fetch with the resource set; bypasses rendering the
            // intermediate form that contains just the Resource block.
            void refreshFormRef.current(withResource);
            return;
          }
        }

        // Adopt server-provided initial/preselect values for any block we have
        // no user-set value for yet.
        const merged: WebModalState = { ...nextValues };
        for (const block of res.blocks) {
          if (block.type === "alert") continue;
          if (merged[block.id] !== undefined) continue;
          if ("value" in block && block.value !== undefined) {
            merged[block.id] = block.value;
          }
        }
        // Replace state only if merging produced changes (avoid an infinite
        // loop where setValues triggers another refresh).
        const changed = Object.keys(merged).some(
          (k) => merged[k] !== nextValues[k]
        );
        if (changed) setValues(merged);
        setState({
          kind: "ready",
          blocks: res.blocks,
          actions: res.actions,
          refreshing: false,
        });
      } catch (err) {
        if (seq !== fetchSeqRef.current) return;
        setState({
          kind: "error",
          error: err instanceof Error ? err.message : String(err),
        });
      }
    },
    [authn, debug]
  );

  // Stable ref so refreshForm can call itself recursively (for the auto-pick
  // resource re-fetch) without recreating the callback on every render.
  const refreshFormRef = useRef(refreshForm);
  refreshFormRef.current = refreshForm;

  // Initial load. Intentionally fire-and-forget on mount only — refreshForm
  // changes on every authn/debug change, which would re-fetch the form.
  const didInitialLoad = useRef(false);
  useEffect(() => {
    if (didInitialLoad.current) return;
    didInitialLoad.current = true;
    void refreshForm({});
  }, [refreshForm]);

  const focusableItems = useMemo(() => {
    if (state.kind !== "ready") return [] as FocusItem[];
    const isFormBlock = (
      b: WebBlock
    ): b is Exclude<WebBlock, { type: "alert" }> => b.type !== "alert";
    // Hide the resource block only when it's a single-option auto-pick — when
    // there are multiple integrations the user needs to pick one.
    const isHiddenResource = (b: WebBlock) =>
      b.id === RESOURCE_SELECTOR_BLOCK_ID &&
      b.type === "static-select" &&
      b.options.length === 1;
    const blockItems: FocusItem[] = state.blocks
      .filter((b) => !b.hidden)
      .filter((b) => !isHiddenResource(b))
      .filter(isFormBlock)
      .map((b) => ({ kind: "block", block: b }));
    const actionItems: FocusItem[] = state.actions.map((a) => ({
      kind: "action",
      action: a,
    }));
    return [...blockItems, ...actionItems];
  }, [state]);

  // Keep focusIndex in bounds when the form re-fetches and the field set changes.
  useEffect(() => {
    if (focusIndex >= focusableItems.length && focusableItems.length > 0) {
      setFocusIndex(focusableItems.length - 1);
    }
  }, [focusableItems.length, focusIndex]);

  const commitFieldValue = useCallback(
    (blockId: string, value: unknown, shouldDispatch: boolean) => {
      const next = { ...values, [blockId]: value };
      setValues(next);
      setMode({ kind: "navigate" });
      // Auto-advance focus past the field the user just set. Bounds-check
      // handled by the effect above when the field set shifts post-dispatch.
      setFocusIndex((i) =>
        focusableItems.length === 0
          ? 0
          : Math.min(i + 1, focusableItems.length - 1)
      );
      if (shouldDispatch) void refreshForm(next);
    },
    [focusableItems.length, refreshForm, values]
  );

  const submit = useCallback(async () => {
    setMode({ kind: "submitting" });
    setSubmitError(null);
    try {
      const res = await submitWebRequest(authn, values, debug);
      if (!res.ok) {
        setSubmitError(res.error);
        setMode({ kind: "navigate" });
        return;
      }
      const ids = res.urls.map((u) => u.split("/").pop() ?? "").filter(Boolean);
      onSubmitted(ids);
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : String(err));
      setMode({ kind: "navigate" });
    }
  }, [authn, debug, onSubmitted, values]);

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
        if (item.action.type === "cancel") onCancel();
        else if (item.action.type === "submit") void submit();
      } else {
        setMode({ kind: "edit", blockId: item.block.id });
      }
    }
  });

  if (state.kind === "loading") {
    return (
      <Box paddingX={1}>
        <Text>
          <Spinner type="dots" /> Loading request form…
        </Text>
      </Box>
    );
  }

  if (state.kind === "error") {
    return (
      <Box flexDirection="column" paddingX={1}>
        <Text color="red">Error: {state.error}</Text>
        <Text dimColor>Press Esc to go back.</Text>
      </Box>
    );
  }

  return (
    <Box flexDirection="column" paddingX={1}>
      <Box>
        <Text bold>Request access</Text>
        {state.refreshing ? (
          <Text dimColor>
            {"  "}
            <Spinner type="dots" /> updating…
          </Text>
        ) : null}
      </Box>
      {submitError ? (
        <Box marginTop={1}>
          <Text color="red">✗ Submit failed: {submitError}</Text>
        </Box>
      ) : null}
      <Box flexDirection="column" marginTop={1}>
        {focusableItems.map((item, i) => {
          const focused = i === focusIndex && mode.kind === "navigate";
          const editing =
            mode.kind === "edit" &&
            item.kind === "block" &&
            mode.blockId === item.block.id;
          if (item.kind === "action") {
            return (
              <ActionRow
                key={`action-${item.action.id}`}
                action={item.action}
                focused={focused}
              />
            );
          }
          return (
            <BlockRow
              key={item.block.id}
              authn={authn}
              block={item.block}
              value={values[item.block.id]}
              values={values}
              focused={focused}
              editing={editing}
              debug={debug}
              onCommit={(v) =>
                commitFieldValue(
                  item.block.id,
                  v,
                  "dispatch" in item.block && item.block.dispatch
                )
              }
              onCancelEdit={() => setMode({ kind: "navigate" })}
            />
          );
        })}
        {state.blocks
          .filter((b) => b.type === "alert" && !b.hidden)
          .map((b) => (
            <AlertRow
              key={b.id}
              block={b as Extract<WebBlock, { type: "alert" }>}
            />
          ))}
      </Box>
      <Box marginTop={1}>
        <Text dimColor>
          {mode.kind === "submitting"
            ? "Submitting…"
            : mode.kind === "edit"
              ? editHintForBlock(state.blocks, mode.blockId)
              : NAV_HINT}
        </Text>
      </Box>
    </Box>
  );
};

type FocusItem =
  | { kind: "action"; action: WebAction }
  | { kind: "block"; block: Exclude<WebBlock, { type: "alert" }> };

const editHintForBlock = (blocks: WebBlock[], blockId: string): string => {
  const b = blocks.find((bb) => bb.id === blockId);
  if (!b) return EDIT_HINT_TEXT;
  if (b.type === "static-select" || b.type === "dynamic-select") {
    return b.multivalued ? EDIT_HINT_SELECT_MULTI : EDIT_HINT_SELECT_SINGLE;
  }
  return EDIT_HINT_TEXT;
};

const AlertRow: React.FC<{
  block: Extract<WebBlock, { type: "alert" }>;
}> = ({ block }) => {
  const color =
    block.variant === "error"
      ? "red"
      : block.variant === "warning"
        ? "yellow"
        : "cyan";
  return (
    <Box marginY={1}>
      <Text color={color}>
        {block.label ? `${block.label}: ` : ""}
        {block.placeholder}
      </Text>
    </Box>
  );
};

const ActionRow: React.FC<{ action: WebAction; focused: boolean }> = ({
  action,
  focused,
}) => {
  const isSubmit = action.type === "submit";
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
        [ {action.label} ]
      </Text>
    </Box>
  );
};

type BlockRowProps = {
  authn: Authn;
  block: Exclude<WebBlock, { type: "alert" }>;
  value: unknown;
  values: WebModalState;
  focused: boolean;
  editing: boolean;
  debug?: boolean;
  onCommit: (value: unknown) => void;
  onCancelEdit: () => void;
};

const BlockRow: React.FC<BlockRowProps> = (props) => {
  const { block, focused, editing } = props;
  const requiresInlineEditor =
    editing && (block.type === "input" || block.type === "toggle");
  const requiresExpandedEditor =
    editing &&
    (block.type === "static-select" || block.type === "dynamic-select");

  return (
    <Box flexDirection="column" marginBottom={0}>
      {/* The label/value row: ❯  LABEL *           value/editor */}
      <Box>
        <Box width={2}>
          <Text color="cyan" bold>
            {focused ? "❯" : " "}
          </Text>
        </Box>
        <Box width={LABEL_WIDTH}>
          <BlockLabel block={block} focused={focused} />
        </Box>
        <Box flexGrow={1}>
          {requiresInlineEditor ? (
            <BlockInlineEditor {...props} />
          ) : requiresExpandedEditor ? (
            <Text dimColor italic>
              ─ editing ─
            </Text>
          ) : (
            <BlockSummary {...props} />
          )}
        </Box>
      </Box>
      {/* Expanded editor area for selects sits underneath the row. */}
      {requiresExpandedEditor ? (
        <Box marginLeft={2 + 2} marginTop={0}>
          <BlockExpandedEditor {...props} />
        </Box>
      ) : null}
      {block.hint && !editing ? (
        <Box marginLeft={2 + LABEL_WIDTH}>
          <Text dimColor>{block.hint}</Text>
        </Box>
      ) : null}
    </Box>
  );
};

// Overrides for backend block labels that don't match how the CLI surfaces
// them to users. The web modal labels the integration picker "Resource"; in
// the terminal that's confusing because the options are integrations (AWS,
// GCP, Postgres, ...), so we render it as "Integration" instead.
const DISPLAY_LABEL_OVERRIDES: Record<string, string> = {
  [RESOURCE_SELECTOR_BLOCK_ID]: "Integration",
};

const BlockLabel: React.FC<{
  block: Exclude<WebBlock, { type: "alert" }>;
  focused: boolean;
}> = ({ block, focused }) => {
  const required = "required" in block && block.required;
  const rawLabel = DISPLAY_LABEL_OVERRIDES[block.id] ?? block.label ?? "";
  const labelText = rawLabel.toUpperCase();
  return (
    <Text>
      <Text color={focused ? "cyan" : "gray"} bold={focused}>
        {labelText}
      </Text>
      {required ? <Text color="yellow"> *</Text> : null}
    </Text>
  );
};

const BlockSummary: React.FC<BlockRowProps> = ({ block, value }) => {
  if (block.type === "toggle") {
    const set = value === true;
    return (
      <Text>
        <Text color={set ? "green" : undefined}>{set ? "[x]" : "[ ]"}</Text>
        {" " + (block.placeholder || block.label || "")}
      </Text>
    );
  }
  if (block.type === "input") {
    const str = typeof value === "string" ? value : "";
    if (!str) {
      return (
        <Text dimColor italic>
          {block.placeholder || "(empty)"}
        </Text>
      );
    }
    return <Text>{str}</Text>;
  }
  // static-select / dynamic-select
  if (block.multivalued) {
    const arr = Array.isArray(value) ? (value as unknown[]) : [];
    if (arr.length === 0) {
      return (
        <Text dimColor italic>
          {block.placeholder || "(none)"}
        </Text>
      );
    }
    const labels = arr.map((v) => {
      const str = String(v);
      const choice = block.options.find((o) => o.value === str);
      return choice ? choice.label : str;
    });
    return <Text>{labels.join(", ")}</Text>;
  }
  if (value === undefined || value === null || value === "") {
    return (
      <Text dimColor italic>
        {block.placeholder || "(none)"}
      </Text>
    );
  }
  const valueStr = String(value);
  const choice = block.options.find((o) => o.value === valueStr);
  if (!choice) {
    return <Text>{valueStr}</Text>;
  }
  return (
    <Text>
      {choice.label}
      {choice.maturity && choice.maturity !== "ga" ? (
        <Text dimColor> ({choice.maturity})</Text>
      ) : null}
    </Text>
  );
};

const BlockInlineEditor: React.FC<BlockRowProps> = (props) => {
  const { block } = props;
  if (block.type === "input") return <TextEditor {...props} block={block} />;
  if (block.type === "toggle") return <ToggleEditor {...props} block={block} />;
  return null;
};

const BlockExpandedEditor: React.FC<BlockRowProps> = (props) => {
  const { block } = props;
  if (block.type === "static-select")
    return <StaticSelectEditor {...props} block={block} />;
  if (block.type === "dynamic-select")
    return <DynamicSelectEditor {...props} block={block} />;
  return null;
};

const TextEditor: React.FC<BlockRowProps & { block: WebInputBlock }> = ({
  block,
  value,
  onCommit,
  onCancelEdit,
}) => {
  const initial = typeof value === "string" ? value : "";
  const [draft, setDraft] = useState(initial);

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
        placeholder={block.placeholder}
      />
    </Box>
  );
};

const ToggleEditor: React.FC<BlockRowProps & { block: WebToggleBlock }> = ({
  block,
  value,
  onCommit,
  onCancelEdit,
}) => {
  const initial = value === true;
  const [on, setOn] = useState(initial);

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
      {" " + (block.placeholder || block.label || "")}{" "}
      <Text dimColor>(space toggles, Enter commits)</Text>
    </Text>
  );
};

const SUGGESTION_DEBOUNCE_MS = 200;
const DYNAMIC_RESULTS_DISPLAY_LIMIT = 8;

const initialMultiValues = (value: unknown): Set<string> => {
  if (!Array.isArray(value)) return new Set();
  return new Set(value.map((v) => String(v)));
};

/**
 * Shared keyboard navigation + selection state for option lists. Both static
 * and dynamic select editors use this. Resets the focused index whenever the
 * options reference changes (e.g., after a dynamic fetch returns new results)
 * while preserving the multi-select set.
 */
const useSelectMenu = (args: {
  options: WebInputChoice[];
  isMulti: boolean;
  initialValue: unknown;
  onCommit: (value: string[] | string) => void;
  onCancel: () => void;
}): { idx: number; selected: Set<string> } => {
  const { options, isMulti, initialValue, onCommit, onCancel } = args;

  const initialIdx = (() => {
    if (isMulti || initialValue === undefined || initialValue === null) {
      return 0;
    }
    const i = options.findIndex((o) => o.value === String(initialValue));
    return i >= 0 ? i : 0;
  })();
  const [idx, setIdx] = useState(initialIdx);
  const [selected, setSelected] = useState<Set<string>>(() =>
    initialMultiValues(initialValue)
  );

  // Reset focus to top whenever the option set changes (typical for dynamic
  // search results). Static options are stable, so this is effectively a
  // no-op for static editors.
  useEffect(() => {
    setIdx(0);
  }, [options]);

  useInput((input, key) => {
    if (key.escape) return onCancel();
    if (key.upArrow) {
      setIdx((i) =>
        options.length === 0 ? 0 : (i + options.length - 1) % options.length
      );
      return;
    }
    if (key.downArrow) {
      setIdx((i) => (options.length === 0 ? 0 : (i + 1) % options.length));
      return;
    }
    if (isMulti && input === " ") {
      const choice = options[idx];
      if (!choice) return;
      setSelected((prev) => {
        const next = new Set(prev);
        if (next.has(choice.value)) next.delete(choice.value);
        else next.add(choice.value);
        return next;
      });
      return;
    }
    if (key.return) {
      if (isMulti) {
        onCommit(Array.from(selected));
      } else {
        const choice = options[idx];
        if (choice) onCommit(choice.value);
      }
    }
  });

  return { idx, selected };
};

const OptionList: React.FC<{
  options: WebInputChoice[];
  idx: number;
  isMulti: boolean;
  selected: Set<string>;
  /** When provided, truncates the visible list and shows a "+ N more" footer. */
  maxDisplay?: number;
  emptyMessage?: string;
}> = ({ options, idx, isMulti, selected, maxDisplay, emptyMessage }) => {
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
        const isSelected = isMulti && selected.has(opt.value);
        const prefix = isMulti
          ? isSelected
            ? "[x] "
            : "[ ] "
          : focused
            ? "› "
            : "  ";
        return (
          <Text key={`${opt.value}-${i}`} color={focused ? "cyan" : undefined}>
            <Text color={isSelected ? "green" : "cyan"}>{prefix}</Text>
            {opt.label}
            {opt.maturity && opt.maturity !== "ga" ? (
              <Text dimColor> ({opt.maturity})</Text>
            ) : null}
          </Text>
        );
      })}
      {overflow > 0 ? (
        <Text dimColor>(+ {overflow} more — narrow your search)</Text>
      ) : null}
    </Box>
  );
};

const StaticSelectEditor: React.FC<
  BlockRowProps & { block: WebStaticSelectBlock }
> = ({ block, value, onCommit, onCancelEdit }) => {
  const isMulti = block.multivalued === true;
  const { idx, selected } = useSelectMenu({
    options: block.options,
    isMulti,
    initialValue: value,
    onCommit,
    onCancel: onCancelEdit,
  });
  return (
    <OptionList
      options={block.options}
      idx={idx}
      isMulti={isMulti}
      selected={selected}
    />
  );
};

const DynamicSelectEditor: React.FC<
  BlockRowProps & { block: WebDynamicSelectBlock }
> = ({ authn, block, value, values, debug, onCommit, onCancelEdit }) => {
  const isMulti = block.multivalued === true;
  const [query, setQuery] = useState("");
  // Form state holds the value string; seed the dropdown with whatever
  // options the form already shipped down (the new fetch will replace them
  // shortly via the debounced effect).
  const [results, setResults] = useState<WebInputChoice[]>(block.options);
  const [loading, setLoading] = useState(false);
  const debouncedQuery = useDebouncedValue(query, SUGGESTION_DEBOUNCE_MS);
  const fetchSeqRef = useRef(0);

  useEffect(() => {
    const seq = ++fetchSeqRef.current;
    setLoading(true);
    void (async () => {
      try {
        const res = await fetchSuggestions(
          authn,
          { listerId: block.id, query: debouncedQuery, values },
          debug
        );
        if (seq !== fetchSeqRef.current) return;
        if (res.ok) setResults(res.suggestions);
      } finally {
        if (seq === fetchSeqRef.current) setLoading(false);
      }
    })();
  }, [authn, block.id, debouncedQuery, debug, values]);

  const { idx, selected } = useSelectMenu({
    options: results,
    isMulti,
    initialValue: value,
    onCommit,
    onCancel: onCancelEdit,
  });

  return (
    <Box flexDirection="column">
      <Box>
        <Text color="cyan">? </Text>
        <TextInput
          value={query}
          onChange={setQuery}
          placeholder={block.placeholder || "Type to search…"}
        />
        {loading ? (
          <Text dimColor>
            {"  "}
            <Spinner type="dots" />
          </Text>
        ) : null}
      </Box>
      <Box flexDirection="column" marginTop={0}>
        <OptionList
          options={results}
          idx={idx}
          isMulti={isMulti}
          selected={selected}
          maxDisplay={DYNAMIC_RESULTS_DISPLAY_LIMIT}
          emptyMessage={loading ? " " : "(no matches)"}
        />
      </Box>
    </Box>
  );
};
