/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../drivers/stdio";
import Sentry from "./sentry";
import { randomUUID } from "crypto";

export const unknownErrorMessage = (errorId: string) =>
  `P0 encountered an unknown error. Please contact support@p0.dev for assistance. (Error ID ${errorId})`;

/** Implements a generic error boundary
 *
 * Logs an error to container logs and Sentry with a unique identifier.
 *
 * @returns A generic error message that should be served to the API caller.
 */
export const errorBoundary = (
  error: any,
  logContext: Record<string, any>,
  debug?: boolean
) => {
  const errorId = randomUUID();
  const errorContext = {
    ...logContext,
    ...error, // Capture any error fields
    errorId,
    message: error.message,
  };

  // TODO: Convert expected errors to a subtype of Error
  if (typeof error === "string") {
    return error;
  } else {
    if (debug) {
      print2(error);
    }
    Sentry.captureException(error, { extra: errorContext, level: "warning" });
    return unknownErrorMessage(errorId);
  }
};
