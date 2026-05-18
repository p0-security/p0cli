/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Authn } from "../types/identity.js";
import React from "react";

export type TuiEntryFlow = "menu" | "request";

export type RunTuiArgs = {
  authn: Authn;
  entry: TuiEntryFlow;
  debug?: boolean;
};

export type RunTuiResult = {
  exitCode: number;
  submittedRequestIds?: string[];
};

/**
 * Mounts the Ink app with the given starting flow and resolves once the user
 * exits (submit, cancel, or ctrl-c). Returns a process-style exit code and
 * any request IDs the user successfully submitted during the session.
 */
export const runTui = async (args: RunTuiArgs): Promise<RunTuiResult> => {
  // Imported lazily so callers that never enter interactive mode don't pay
  // the cost of loading Ink / React on startup.
  const { render } = await import("ink");
  const { App } = await import("./App.js");

  return await new Promise<RunTuiResult>((resolve) => {
    const instance = render(
      React.createElement(App, {
        authn: args.authn,
        entry: args.entry,
        debug: args.debug,
        onExit: (
          exitCode: number,
          info?: { submittedRequestIds?: string[] }
        ) => {
          instance.unmount();
          resolve({ exitCode, submittedRequestIds: info?.submittedRequestIds });
        },
      }),
      { exitOnCtrlC: false }
    );
  });
};
