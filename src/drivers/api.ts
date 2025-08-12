/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Authn } from "../types/identity";
import { p0VersionInfo } from "../version";
import { getTenantConfig } from "./config";
import { defaultConfig } from "./env";
import { print2 } from "./stdio";
import * as path from "node:path";
import yargs from "yargs";

const DEFAULT_PERMISSION_REQUEST_TIMEOUT = 300e3; // 5 minutes

const tenantOrgUrl = (tenant: string) =>
  `${getTenantConfig()?.appUrl ?? defaultConfig.appUrl}/orgs/${tenant}`;
const tenantUrl = (tenant: string) => `${getTenantConfig().appUrl}/o/${tenant}`;
const publicKeysUrl = (tenant: string) =>
  `${tenantUrl(tenant)}/integrations/ssh/public-keys`;
const sshAuditUrl = (tenant: string) =>
  `${tenantUrl(tenant)}/integrations/ssh/audit`;

const commandUrl = (tenant: string) => `${tenantUrl(tenant)}/command/`;
const adminLsCommandUrl = (tenant: string) => `${tenantUrl(tenant)}/command/ls`;
export const tracesUrl = (tenant: string) => `${tenantUrl(tenant)}/traces`;

export const fetchOrgData = async <T>(orgId: string) =>
  unauthenticatedApiFetch<T>(tenantOrgUrl(orgId), "GET");

export const fetchAccountInfo = async <T>(authn: Authn) =>
  baseFetch<T>(authn, {
    url: `${tenantUrl(authn.identity.org.slug)}/account`,
    method: "GET",
  });

export const fetchPermissionRequestDetails = async <T>(
  authn: Authn,
  requestId: string
) =>
  baseFetch<T>(authn, {
    url: `${tenantUrl(authn.identity.org.slug)}/permission-requests/${requestId}`,
    method: "GET",
    maxTimeoutMs: DEFAULT_PERMISSION_REQUEST_TIMEOUT,
  });

export const fetchIntegrationConfig = async <T>(
  authn: Authn,
  integration: string
) =>
  baseFetch<T>(authn, {
    url: `${tenantUrl(authn.identity.org.slug)}/integrations/${integration}/config`,
    method: "GET",
  });

export const fetchStreamingCommand = async function* <T>(
  authn: Authn,
  args: yargs.ArgumentsCamelCase,
  argv: string[]
) {
  yield* fetchWithStreaming<T>(authn, {
    url: commandUrl(authn.identity.org.slug),
    method: "POST",
    body: JSON.stringify({
      argv,
      scriptName: path.basename(args.$0),
      wait: true,
    }),
  });
};

export const fetchCommand = async <T>(
  authn: Authn,
  args: yargs.ArgumentsCamelCase,
  argv: string[]
) =>
  baseFetch<T>(authn, {
    url: commandUrl(authn.identity.org.slug),
    method: "POST",
    body: JSON.stringify({
      argv,
      scriptName: path.basename(args.$0),
    }),
  });

/** Special admin 'ls' command that can retrieve results for all users. Requires 'owner' permission. */
export const fetchAdminLsCommand = async <T>(
  authn: Authn,
  args: yargs.ArgumentsCamelCase,
  argv: string[]
) =>
  baseFetch<T>(authn, {
    url: adminLsCommandUrl(authn.identity.org.slug),
    method: "POST",
    body: JSON.stringify({
      argv,
      scriptName: path.basename(args.$0),
    }),
  });

export const submitPublicKey = async <T>(
  authn: Authn,
  args: { publicKey: string; requestId: string }
) =>
  baseFetch<T>(authn, {
    url: publicKeysUrl(authn.identity.org.slug),
    method: "POST",
    body: JSON.stringify({
      requestId: args.requestId,
      publicKey: args.publicKey,
    }),
  });

export const fetchWithStreaming = async function* <T>(
  authn: Authn,
  args: {
    url: string;
    method: string;
    body?: string;
    maxTimeoutMs?: number;
  }
) {
  const token = await authn.getToken();
  const { version } = p0VersionInfo;
  const { url, method, body, maxTimeoutMs } = args;
  const fetchOptions = {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "User-Agent": `P0 CLI/${version}`,
    },
    body,
    keepalive: true,
  };
  const textDecoder = new TextDecoder();
  try {
    const response = await fetch(
      url,
      maxTimeoutMs
        ? { ...fetchOptions, signal: AbortSignal.timeout(maxTimeoutMs) }
        : fetchOptions
    );
    const reader = response.body?.getReader();
    if (!reader) throw `No reader available`;
    while (true) {
      const read = await reader.read();
      if (read.done) {
        break;
      }
      const value = read.value;
      const text = textDecoder.decode(value);
      const jsonlSegments = text.split("\n").filter(Boolean);
      for (const segment of jsonlSegments) {
        const parsedResponse = JSON.parse(segment);
        if (parsedResponse.type === "error") {
          throw parsedResponse.error;
        }
        if (parsedResponse.type === "heartbeat") {
          continue;
        }
        if (parsedResponse.type !== "data" || !("data" in parsedResponse)) {
          throw "Invalid response from the server";
        }
        const { data } = parsedResponse;
        if ("error" in data) {
          throw data.error;
        }
        yield data as T;
      }
    }
  } catch (error) {
    if (
      error instanceof TypeError &&
      (error.message === "fetch failed" || error.message === "terminated")
    ) {
      throw `Network error: Unable to reach the server.`;
    } else {
      throw error;
    }
  }
};

export const auditSshSessionActivity = async (args: {
  authn: Authn;
  requestId: string;
  sshSessionId: string;
  action: `ssh.session.${"end" | "start"}`;
  debug: boolean | undefined;
}) => {
  const { authn, requestId, action, sshSessionId, debug } = args;

  if (debug) {
    print2(
      `Submitting audit log for request: ${requestId}, action: ${action}, sshSessionId: ${sshSessionId}`
    );
  }

  try {
    await baseFetch(authn, {
      url: sshAuditUrl(authn.identity.org.slug),
      method: "POST",
      body: JSON.stringify({
        requestId,
        action,
        sshSessionId,
      }),
    });
    if (debug) {
      print2(`Audit log submitted for request: ${requestId}`);
    }
  } catch (error) {
    if (debug) {
      print2(`Failed to submit audit log for request: ${requestId}`);
      print2(`Error: ${JSON.stringify(error)}`);
    }
  }
};

export const baseFetch = async <T>(
  authn: Authn,
  args: {
    url: string;
    method: string;
    body?: string;
    maxTimeoutMs?: number;
  }
) => {
  const { version } = p0VersionInfo;
  const { url, method, body, maxTimeoutMs } = args;
  const token = await authn.getToken();
  const fetchOptions = {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "User-Agent": `P0 CLI/${version}`,
    },
    body,
    keepalive: true,
  };

  try {
    const response = await fetch(
      url,
      maxTimeoutMs
        ? { ...fetchOptions, signal: AbortSignal.timeout(maxTimeoutMs) }
        : fetchOptions
    );
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

const unauthenticatedApiFetch = async <T>(
  url: string,
  method: string,
  body?: string
) => {
  const { version } = p0VersionInfo;
  try {
    const fetchConfig = {
      method,
      headers: {
        "Content-Type": "application/json",
        "User-Agent": `P0 CLI/${version}`,
      },
    };
    const response = await fetch(url, {
      ...fetchConfig,
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
