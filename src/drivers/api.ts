/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Authn } from "../types/identity";
import { p0VersionInfo } from "../version";
import { getTenantConfig } from "./config";
import * as path from "node:path";
import yargs from "yargs";

const DEFAULT_PERMISSION_REQUEST_TIMEOUT = 300e3; // 5 minutes

const tenantUrl = (tenant: string) => `${getTenantConfig().appUrl}/o/${tenant}`;
const publicKeysUrl = (tenant: string) =>
  `${tenantUrl(tenant)}/integrations/ssh/public-keys`;

const commandUrl = (tenant: string) => `${tenantUrl(tenant)}/command/`;
const adminLsCommandUrl = (tenant: string) => `${tenantUrl(tenant)}/command/ls`;
export const tracesUrl = (tenant: string) => `${tenantUrl(tenant)}/traces`;

export const fetchAccountInformation = async <T>(authn: Authn) =>
  baseFetch<T>(authn, {
    url: `${tenantUrl(authn.identity.org.slug)}/account`,
    method: "GET",
  });

export const fetchPermissionRequest = async <T>(
  authn: Authn,
  requestId: string
) =>
  baseFetch<T>(authn, {
    url: `${tenantUrl(authn.identity.org.slug)}/permission-requests/${requestId}?waitForResolution=true`,
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
  yield* streamingApiFetch<T>(authn, {
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

export const streamingApiFetch = async function* <T>(
  authn: Authn,
  args: {
    url: string;
    method: string;
    body?: string;
    maxTimeoutMs?: number;
  }
) {
  const token = await authn.userCredential.user.getIdToken();
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
      const parsedResponse = JSON.parse(text);
      if (parsedResponse.type === "heartbeat") {
        continue;
      }
      if (parsedResponse.type !== "data" || !("data" in parsedResponse)) {
        throw new Error("Invalid response from the server");
      }
      const { data } = parsedResponse;
      if ("error" in data) {
        throw data.error;
      }
      yield data as T;
    }
  } catch (error) {
    if (error instanceof TypeError && error.message === "fetch failed") {
      throw `Network error: Unable to reach the server at ${url}.`;
    } else {
      throw error;
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
  const token = await authn.userCredential.user.getIdToken();
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

export const apiFetch = async <T>(
  url: string,
  method: string,
  body?: string
) => {
  const { version } = await p0VersionInfo;
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
