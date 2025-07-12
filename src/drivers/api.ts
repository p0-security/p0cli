/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Authn } from "../types/identity";
import { p0VersionInfo } from "../version";
import { getTenantConfig } from "./config";
import { print2 } from "./stdio";
import * as path from "node:path";
import yargs from "yargs";

const tenantUrl = (tenant: string) => `${getTenantConfig().appUrl}/o/${tenant}`;
const publicKeysUrl = (tenant: string) =>
  `${tenantUrl(tenant)}/integrations/ssh/public-keys`;
const sshAuditUrl = (tenant: string) =>
  `${tenantUrl(tenant)}/integrations/ssh/audit`;

const commandUrl = (tenant: string) => `${tenantUrl(tenant)}/command/`;
const adminLsCommandUrl = (tenant: string) => `${tenantUrl(tenant)}/command/ls`;
export const tracesUrl = (tenant: string) => `${tenantUrl(tenant)}/traces`;

export const fetchCommand = async <T>(
  authn: Authn,
  args: yargs.ArgumentsCamelCase,
  argv: string[]
) =>
  baseFetch<T>(
    authn,
    commandUrl(authn.identity.org.slug),
    "POST",
    JSON.stringify({
      argv,
      scriptName: path.basename(args.$0),
    })
  );

/** Special admin 'ls' command that can retrieve results for all users. Requires 'owner' permission. */
export const fetchAdminLsCommand = async <T>(
  authn: Authn,
  args: yargs.ArgumentsCamelCase,
  argv: string[]
) =>
  baseFetch<T>(
    authn,
    adminLsCommandUrl(authn.identity.org.slug),
    "POST",
    JSON.stringify({
      argv,
      scriptName: path.basename(args.$0),
    })
  );

export const submitPublicKey = async <T>(
  authn: Authn,
  args: { publicKey: string; requestId: string }
) =>
  baseFetch<T>(
    authn,
    publicKeysUrl(authn.identity.org.slug),
    "POST",
    JSON.stringify({
      requestId: args.requestId,
      publicKey: args.publicKey,
    })
  );

export const auditSshSessionActivity = async (args: {
  authn: Authn;
  docId: string;
  sessionId: string;
  action: `${"proxy" | "scp" | "ssh"}.session.${"end" | "start"}`;
  debug: boolean | undefined;
}) => {
  const { authn, docId, action, sessionId, debug } = args;

  if (debug) {
    print2(`Submitting audit log for request: ${docId}`);
    print2(`Action: ${action}`);
    print2(`Session ID: ${sessionId}`);
  }

  try {
    await baseFetch(
      authn,
      sshAuditUrl(authn.identity.org.slug),
      "POST",
      JSON.stringify({
        docId,
        action,
        sessionId,
      })
    );
    if (debug) {
      print2(`Audit log submitted for request: ${docId}`);
    }
  } catch (error) {
    if (debug) {
      print2(`Failed to submit audit log for request: ${docId}`);
      print2(`Error: ${JSON.stringify(error)}`);
    }
  }
};

export const baseFetch = async <T>(
  authn: Authn,
  url: string,
  method: string,
  body: string
) => {
  const token = await authn.userCredential.user.getIdToken();
  const { version } = p0VersionInfo;

  try {
    const response = await fetch(url, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "User-Agent": `P0 CLI/${version}`,
      },
      body,
    });
    const text = await response.text();
    const data = JSON.parse(text);
    if ("error" in data) {
      throw data.error;
    }
    return data as T;
  } catch (error) {
    if (error instanceof TypeError && error.message === "fetch failed") {
      throw `Network error: Unable to reach the server at ${url}.`;
    } else {
      throw error;
    }
  }
};
