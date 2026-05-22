/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

/**
 * Schema for one field in a workflow's interactive form. Mirrors the
 * structure of the underlying yargs option / positional so the form
 * collects exactly what the non-interactive command would receive.
 */
export type WorkflowField =
  | {
      /**
       * Server-backed search-and-select, powered by the same `p0 ls`
       * listing endpoint the request form's dynamic dropdowns use.
       * The user types a query; results stream in from the backend;
       * the picked `value` is what we pass to the executor.
       */
      kind: "dynamic-select";
      key: string;
      label: string;
      help?: string;
      required?: boolean;
      placeholder?: string;
      positional?: boolean;
      /**
       * Description of how to populate the suggestion list. `argv` is
       * the tail passed to `p0 ls` (e.g. `["ssh", "session",
       * "destination"]`); the user's current query is appended. Some
       * listers require companion options derived from other form
       * fields (e.g. the k8s role lister needs `--cluster <id>`);
       * those go in `dependsOn`.
       */
      lister: {
        argv: string[];
        /**
         * Form fields whose values become `--<flag> <value>` options on
         * the lister call. If a referenced field is empty the option
         * is omitted (the backend usually treats that as "no filter").
         */
        dependsOn?: { flag: string; field: string }[];
      };
      /**
       * If true, the user can also accept a free-typed value that's
       * not in the suggestion list (useful when the lister might miss
       * recently-added resources). Default false.
       */
      allowFreeText?: boolean;
    }
  | {
      /** Free-form whitespace-separated args appended after `--`. */
      kind: "passthrough";
      key: string;
      label: string;
      help?: string;
    }
  | {
      kind: "select";
      key: string;
      label: string;
      help?: string;
      required?: boolean;
      options: { label: string; value: string }[];
      defaultValue?: string;
      /** True for positional args; affects CLI preview rendering. */
      positional?: boolean;
      /**
       * If set, render this field as `••••` in the CLI preview while
       * still passing the real value to the executor.
       */
      sensitive?: boolean;
    }
  | {
      kind: "text";
      key: string;
      label: string;
      help?: string;
      placeholder?: string;
      required?: boolean;
      defaultValue?: string;
      positional?: boolean;
      sensitive?: boolean;
    }
  | {
      kind: "toggle";
      key: string;
      label: string;
      help?: string;
      defaultValue?: boolean;
    };

/**
 * Declarative description of a workflow — everything the TUI needs to
 * (a) render a form, (b) preview the equivalent CLI command, and (c)
 * hand the collected values to an executor.
 */
export type WorkflowSpec = {
  /** Stable identifier used as the dynamic-select option value. */
  id: string;
  /** Command path tokens, e.g. ["aws", "rds", "generate-db-auth-token"]. */
  command: string[];
  description: string;
  /** Optional aliases / keywords the workflow picker matches against. */
  searchTokens?: string[];
  fields: WorkflowField[];
};

/** Values collected from the form, keyed by field.key. */
export type WorkflowValues = Record<
  string,
  string[] | boolean | string | undefined
>;
