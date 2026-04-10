/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { signProxyToken } from "../../common/jwt";
import { createKeyPair } from "../../common/keys";
import { print2 } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import { ProxyRdpRequest } from "../../types/rdp";
import { PermissionRequest } from "../../types/request";
import { exec, getOperatingSystem } from "../../util";
import { getUserAgent } from "../../version";
import * as fs from "node:fs";
import tmp from "tmp-promise";

type CreateSessionResponse = {
  session_id: string;
  proxy_host: string;
  proxy_port: number;
  rdp_file_content: string;
  state: string;
  created_at: string;
  token_expires_at: string;
};

const createSession = async (
  request: PermissionRequest<ProxyRdpRequest>,
  options: { debug?: boolean; privateKey: string }
): Promise<CreateSessionResponse> => {
  const { debug, privateKey } = options;
  const { instanceId } = request.permission.resource;
  const { bastionUrl } = request.generated;

  const token = signProxyToken({
    principal: request.principal,
    target: instanceId,
    privateKey,
  });

  const body = JSON.stringify({
    hostname: instanceId,
  });

  if (debug) {
    print2(`Creating proxy RDP session for target: ${instanceId}`);
    print2(`API endpoint: ${bastionUrl}/api/sessions`);
  }

  const response = await fetch(`${bastionUrl}/api/sessions`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "User-Agent": getUserAgent(),
    },
    body,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(
      `Failed to create proxy RDP session: ${response.status} ${response.statusText} - ${text}`
    );
  }

  return (await response.json()) as CreateSessionResponse;
};

const saveRdpFile = async (
  rdpContent: string,
  options: { debug?: boolean }
): Promise<string> => {
  const { debug } = options;

  const { path: tmpPath } = await tmp.file({
    mode: 0o600,
    prefix: "p0cli-",
    postfix: ".rdp",
    discardDescriptor: true,
  });

  await fs.promises.writeFile(tmpPath, rdpContent, { encoding: "utf-8" });

  // Resolve 8.3 short paths (e.g. MIGUEL~1) to long paths, as mstsc
  // on Windows cannot open files referenced by short names.
  const resolvedPath = await fs.promises.realpath(tmpPath);

  if (debug) {
    print2(`RDP file saved to: ${resolvedPath}`);
  }

  return resolvedPath;
};

const openRdpFile = async (
  rdpFilePath: string,
  options: { debug?: boolean }
) => {
  const { debug } = options;
  const os = getOperatingSystem();

  let command: string;
  let args: string[];

  if (os === "mac") {
    command = "open";
    args = [rdpFilePath];
  } else if (os === "win") {
    command = "mstsc";
    args = [rdpFilePath];
  } else {
    throw new Error(`RDP proxy connections are not supported on ${os}`);
  }

  if (debug) {
    print2(`Executing: ${command} ${args.join(" ")}`);
  }

  await exec(command, args, { check: true });
};

export const proxyRdpProvider = {
  setup: async (
    request: PermissionRequest<ProxyRdpRequest>,
    options: { debug?: boolean }
  ) => {
    if (options.debug) {
      print2("Setting up proxy RDP connection...");
      print2(`Target instance: ${request.permission.resource.instanceId}`);
    }
  },

  spawnConnection: async (
    _authn: Authn,
    request: PermissionRequest<ProxyRdpRequest>,
    options: {
      configure?: boolean;
      debug?: boolean;
    }
  ) => {
    const { debug } = options;

    const { privateKey } = await createKeyPair();

    if (debug) {
      print2("Creating proxy RDP connection...");
      print2(`Target instance: ${request.permission.resource.instanceId}`);
    }

    const session = await createSession(request, {
      ...options,
      privateKey,
    });

    if (debug) {
      print2(`Session created: ${JSON.stringify(session)}`);
    }

    const rdpFilePath = await saveRdpFile(session.rdp_file_content, {
      debug,
    });

    print2("Opening RDP session...");
    await openRdpFile(rdpFilePath, { debug });
  },
};
