/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

// Mirrors app/shared/src/integrations/notifiers/web-requests/types.ts.
// Kept in sync manually because the CLI and app are separate packages.

export type Maturity = "beta" | "deprecated" | "ga" | "preview";

export type WebModalState = Record<string, any>;

export type WebInputChoice = {
  label: string;
  icon?: string;
  value: string;
  group: string;
  maturity: Maturity;
};

export type WebAction = {
  id: string;
  type: "cancel" | "submit";
  label: string;
};

export type WebBlockBase = {
  id: string;
  label: string;
  placeholder: string;
  hint?: string;
  hidden?: boolean;
};

export type WebBlockFormBase = WebBlockBase & {
  dispatch: boolean;
  required: boolean;
  multiline?: boolean;
  isPreselect?: boolean;
};

export type WebAlertBlock = WebBlockBase & {
  type: "alert";
  variant: "error" | "info" | "warning";
};

export type WebInputBlock = WebBlockFormBase & {
  type: "input";
  multivalued: false;
  value?: string;
};

export type WebMultivalued =
  | { multivalued: false; value?: WebInputChoice }
  | { multivalued: true; value?: WebInputChoice[] };

export type WebSelectBlockBase = WebBlockFormBase &
  WebMultivalued & {
    options: WebInputChoice[];
    multiline?: false;
  };

export type WebDynamicSelectBlock = WebSelectBlockBase & {
  type: "dynamic-select";
};

export type WebStaticSelectBlock = WebSelectBlockBase & {
  type: "static-select";
};

export type WebToggleBlock = WebBlockFormBase & {
  type: "toggle";
  value?: boolean;
};

export type WebStringBlock =
  | WebDynamicSelectBlock
  | WebInputBlock
  | WebStaticSelectBlock;

export type WebBlock = WebAlertBlock | WebStringBlock | WebToggleBlock;

export type WebFormBlock = Exclude<WebBlock, WebAlertBlock>;

export type GetRequestModalRequestBody = { values: WebModalState };
export type GetRequestModalResponseBody =
  | {
      ok: true;
      blocks: WebBlock[];
      actions: WebAction[];
      supportedResources: string[];
    }
  | { ok: false; error: string };

export type GetSuggestionsRequestBody = {
  listerId: string;
  query: string;
  values: WebModalState;
};
export type GetSuggestionsResponseBody =
  | { ok: false; error: string }
  | { ok: true; suggestions: WebInputChoice[] };

export type SubmitRequestRequestBody = { values: WebModalState };
export type SubmitRequestResponseBody =
  | { ok: false; error: string }
  | { ok: true; urls: string[] };

// Reserved block IDs the backend uses to identify well-known fields.
// Mirrors app/shared/src/integrations/notifiers/constants.ts.
export const RESOURCE_SELECTOR_BLOCK_ID = "p0_resource_block";
export const ACCESS_TYPE_BLOCK_ID = "p0_access_type_block";
export const REASON_BLOCK_ID = "reason_input_block";
export const REQUEST_TIME_BLOCK_ID = "requested_duration_input_block";
export const ERROR_BLOCK_ID = "p0_error";
