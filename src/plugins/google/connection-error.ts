/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { GcpSshRequest } from "./types";

/**
 * P0 grants the IAM roles needed for GCP SSH, but OS Login must be enabled in
 * the customer's project — P0 cannot enable it on their behalf. When OS Login is
 * off the IAM grant still succeeds, but the connection fails at SSH
 * authentication: without OS Login the user's key is never provisioned onto the
 * VM (P0's grant does not include permission to write keys to instance
 * metadata), so auth is rejected with `Permission denied (publickey)`.
 *
 * Historically the user saw only that raw, generic rejection and concluded P0
 * was broken. We surface a targeted hint instead. `Permission denied
 * (publickey)` is not exclusively an OS Login problem — it can also be a brief
 * key-propagation delay or a just-granted IAM role — so the message names OS
 * Login as the most likely cause while listing the alternatives, and never
 * claims certainty.
 *
 * We deliberately do NOT try to classify the other GCP prerequisite failure (IAP
 * / firewall not configured, which fails earlier, at the gcloud tunnel rather
 * than at SSH auth). Its `gcloud start-iap-tunnel` error strings vary by gcloud
 * version and are easy to misattribute; since misattributing is worse than the
 * status quo, those failures fall through to the raw error unchanged.
 */

export const GCP_SSH_PREREQUISITES_DOC =
  "https://docs.p0.dev/integrations/resource-integrations/ssh#gcp-project-requirements";

/** SSH auth was reached and rejected — most likely because OS Login is off. */
const AUTH_REJECTED_PATTERN = /Permission denied \(publickey\)/;

// Leads with a newline so it prints with one blank line above the preceding SSH
// output, for legibility.
const osLoginMessage = (instance: string) =>
  `\nConnected to ${instance} but authentication was rejected ` +
  `(Permission denied (publickey)). The most common cause is OS Login not ` +
  `being enabled. Enable it by setting enable-oslogin=TRUE on the project (or ` +
  `instance) metadata, then retry. If OS Login is already enabled, this can ` +
  `also be a brief key-propagation delay or a just-granted IAM role — wait ` +
  `~30s and retry. See ${GCP_SSH_PREREQUISITES_DOC}`;

/**
 * Inspects the captured stderr of a failed GCP SSH connection and returns an
 * actionable message when the failure is an SSH auth rejection (most likely OS
 * Login not being enabled), or `undefined` to fall through to the raw error.
 */
export const classifyGcpConnectionError = (
  stderr: string,
  request: Pick<GcpSshRequest, "id">
): string | undefined =>
  AUTH_REJECTED_PATTERN.test(stderr) ? osLoginMessage(request.id) : undefined;
