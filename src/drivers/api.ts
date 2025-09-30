/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { regenerateWithSleep, retryWithSleep } from "../common/retry";
import { Authn } from "../types/identity";
import { p0VersionInfo } from "../version";
import { getTenantConfig } from "./config";
import { defaultConfig } from "./env";
import { print2 } from "./stdio";
import * as path from "node:path";
import yargs from "yargs";

// We retry with these delays: 1s, 2s, 4s, 8s, 16s, 30s, 30s, 30s
// for a total of 121s wait time over 8 retries (ignoring jitter)
const RETRY_OPTIONS = {
  shouldRetry: (error: unknown) =>
    error === "HTTP Error: 429 Too Many Requests",
  retries: 8,
  delayMs: 1_000,
  multiplier: 2.0,
  maxDelayMs: 30_000,
};

const tenantOrgUrl = (tenant: string) =>
  `${getTenantConfig()?.appUrl ?? defaultConfig.appUrl}/orgs/${tenant}`;
const tenantUrl = (tenant: string) => `${getTenantConfig().appUrl}/o/${tenant}`;
const publicKeysUrl = (tenant: string) =>
  `${tenantUrl(tenant)}/integrations/ssh/public-keys`;
const certSignRequestUrl = (tenant: string) =>
  `${tenantUrl(tenant)}/integrations/ssh/certificates`;
const sshAuditUrl = (tenant: string) =>
  `${tenantUrl(tenant)}/integrations/ssh/audit`;

const commandUrl = (tenant: string) => `${tenantUrl(tenant)}/command/`;
const adminLsCommandUrl = (tenant: string) => `${tenantUrl(tenant)}/command/ls`;
export const tracesUrl = (tenant: string) => `${tenantUrl(tenant)}/traces`;

export const fetchOrgData = async <T>(orgId: string) =>
  baseFetch<T>({ url: tenantOrgUrl(orgId), method: "GET" });

export const fetchAccountInfo = async <T>(authn: Authn, debug?: boolean) =>
  authFetch<T>(authn, {
    url: `${tenantUrl(authn.identity.org.slug)}/account`,
    method: "GET",
    debug,
  });

export const fetchIntegrationConfig = async <T>(
  authn: Authn,
  integration: string,
  debug?: boolean
) =>
  authFetch<T>(authn, {
    url: `${tenantUrl(authn.identity.org.slug)}/integrations/${integration}/config`,
    method: "GET",
    debug,
  });

export const fetchStreamingCommand = async function* <T>(
  authn: Authn,
  args: yargs.ArgumentsCamelCase,
  argv: string[],
  debug?: boolean
) {
  yield* fetchWithStreaming<T>(
    authn,
    {
      url: commandUrl(authn.identity.org.slug),
      method: "POST",
      body: JSON.stringify({
        argv,
        scriptName: path.basename(args.$0),
        wait: true,
      }),
    },
    debug
  );
};

export const fetchCommand = async <T>(
  authn: Authn,
  args: yargs.ArgumentsCamelCase<{ debug?: boolean }>,
  argv: string[]
) =>
  authFetch<T>(authn, {
    url: commandUrl(authn.identity.org.slug),
    method: "POST",
    body: JSON.stringify({
      argv,
      scriptName: path.basename(args.$0),
    }),
    debug: args.debug,
  });

/** Special admin 'ls' command that can retrieve results for all users. Requires 'owner' permission. */
export const fetchAdminLsCommand = async <T>(
  authn: Authn,
  args: yargs.ArgumentsCamelCase<{ debug?: boolean }>,
  argv: string[]
) =>
  authFetch<T>(authn, {
    url: adminLsCommandUrl(authn.identity.org.slug),
    method: "POST",
    body: JSON.stringify({
      argv,
      scriptName: path.basename(args.$0),
    }),
    debug: args.debug,
  });

export const submitPublicKey = async <T>(
  authn: Authn,
  args: { publicKey: string; requestId: string },
  debug?: boolean
) =>
  authFetch<T>(authn, {
    url: publicKeysUrl(authn.identity.org.slug),
    method: "POST",
    body: JSON.stringify({
      requestId: args.requestId,
      publicKey: args.publicKey,
    }),
    debug,
  });

export const certificateSigningRequest = async (
  authn: Authn,
  args: { publicKey: string; requestId: string }
) =>
  authFetch<{ signedCertificate: string }>(authn, {
    url: certSignRequestUrl(authn.identity.org.slug),
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
  },
  debug?: boolean
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

  const attemptFetch = async function* () {
    const response = await fetch(
      url,
      maxTimeoutMs
        ? { ...fetchOptions, signal: AbortSignal.timeout(maxTimeoutMs) }
        : fetchOptions
    );

    if (!response.body) throw "No reader available";
    const onLine = (line: string) => {
      const segment = JSON.parse(line);
      if (segment.type === "error") {
        throw segment.error;
      }
      if (segment.type !== "heartbeat") {
        if (segment.type !== "data" || !("data" in segment)) {
          throw "Invalid response from the server";
        }
        const { data } = segment;
        if ("error" in data) {
          throw data.error;
        }
        return data as T;
      }
      return undefined; // Ignore heartbeat messages
    };
    // we need get the reader from the body as the backend will be streaming chunks of stringified json
    // response data delimited using new lines.
    const reader = response.body.getReader();
    const decoder = new TextDecoder(); // utf-8 by default

    // given the reader.read() can return partial data due to buffering at network level
    // there is chance we may get the data from reader.read() that might be incomplete json
    // or json chunk without the new line delimiter
    // we initialize an empty buffer to keep track of
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      // Decode this chunk and append to buffer. {stream:true} preserves
      // multi-byte code points that might be split across chunks.
      buffer += decoder.decode(value, { stream: true });
      if (debug) print2(`\n[API:stream] Processing buffer: ${buffer}`);
      // Split on both Unix and Windows newlines; keep the last (possibly partial) piece in buffer.
      const parts = buffer.split(/\r?\n/);
      buffer = parts.pop() ?? "";

      for (const line of parts) {
        const response = onLine(line);
        if (response) {
          yield response;
        }
      }
    }
    // do not handle the left over buffer as it may contain partial json and the backend is always expected to send complete json objects
    if (buffer.length > 0) {
      // this should not happen in most scenarios except errors
      if (debug) {
        print2(
          "[API:stream] Remaining data received from the server but not processed due to the lack of new-line: " +
            buffer
        );
      }
      // there is a chance that the server could have errored with a non-streaming response
      // - we hit an errorBoundary in the backend and we received a valid json without a new-line delimiter at the end
      // - or the load balancer in front of the backend errored out and returned a html error page
      try {
        if (debug) {
          print2(
            "[API:stream] Trying to parse to validate json completeness: " +
              buffer
          );
        }
        handleResponse(response, buffer);
      } catch (err) {
        // If this is a json parse error then we have received a partial response
        // we could throw an error saying incomplete response from the server
        // else rethrow the error
        if (err instanceof SyntaxError) {
          // log the error in debug logs
          if (debug) {
            print2(
              "[API:stream] Failed to parse JSON from server response: " +
                String(err)
            );
          }
          throw "Invalid response from the server";
        } else {
          throw err;
        }
      }
    }
  };

  try {
    yield* regenerateWithSleep(() => attemptFetch(), {
      ...RETRY_OPTIONS,
      debug,
    });
  } catch (error) {
    if (
      error instanceof TypeError &&
      (error.message === "fetch failed" || error.message === "terminated")
    ) {
      if (debug) {
        print2("Network error: " + String(error));
      }
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
    await authFetch(authn, {
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

const baseFetch = async <T>(args: {
  url: string;
  method: string;
  body?: string;
  headers?: Record<string, string>;
  maxTimeoutMs?: number;
  debug?: boolean;
}) => {
  const { version } = p0VersionInfo;
  const { url, method, body, maxTimeoutMs, headers } = args;
  const fetchOptions = {
    method,
    headers: {
      ...(headers ?? {}),
      "Content-Type": "application/json",
      "User-Agent": `P0 CLI/${version}`,
    },
    body,
    keepalive: true,
    ...(maxTimeoutMs ? { signal: AbortSignal.timeout(maxTimeoutMs) } : {}),
  };

  const attemptFetch = async () => {
    const response = await fetch(url, fetchOptions);
    const text = await response.text();
    return handleResponse(response, text) as T;
  };

  try {
    return await retryWithSleep(() => attemptFetch(), {
      ...RETRY_OPTIONS,
      debug: args.debug,
    });
  } catch (error) {
    if (error instanceof TypeError && error.message === "fetch failed") {
      throw `Network error: Unable to reach the server at ${url}.`;
    } else {
      throw error;
    }
  }
};

const authFetch = async <T>(
  authn: Authn,
  args: {
    url: string;
    method: string;
    body?: string;
    maxTimeoutMs?: number;
    debug?: boolean;
  }
) => {
  const token = await authn.getToken();
  const headers = {
    authorization: `Bearer ${token}`,
  };
  return baseFetch<T>({
    ...args,
    headers,
  });
};

const handleResponse = (response: Response, responseText: string) => {
  let data;
  try {
    data = JSON.parse(responseText);
  } catch (err) {
    if ("ok" in response && !response.ok) {
      throw `HTTP Error: ${response.status} ${response.statusText}`;
    } else {
      throw "Invalid response from the server";
    }
  }

  if ("error" in data) {
    throw data.error;
  }
  return data;
};
