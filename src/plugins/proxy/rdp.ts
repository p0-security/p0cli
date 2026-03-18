/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
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
  rdp_file_url: string;
  state: string;
  created_at: string;
  token_expires_at: string;
};

const createSession = async (
  request: PermissionRequest<ProxyRdpRequest>,
  options: { debug?: boolean; user?: string }
): Promise<CreateSessionResponse> => {
  const { debug, user } = options;
  const { instanceId } = request.permission.resource;
  const { bastionUrl, bastionApiKey } = request.generated;

  const body = JSON.stringify({
    target_id: instanceId,
    username: user,
    user_id: request.principal,
  });

  if (debug) {
    print2(`Creating proxy RDP session for target: ${instanceId}`);
  }

  const response = await fetch(`${bastionUrl}/api/sessions`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bastionApiKey}`,
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

const downloadRdpFile = async (
  request: PermissionRequest<ProxyRdpRequest>,
  session: CreateSessionResponse,
  options: { debug?: boolean }
): Promise<string> => {
  const { debug } = options;
  const { bastionUrl, bastionApiKey } = request.generated;

  if (debug) {
    print2(`Downloading RDP file for session: ${session.session_id}`);
  }

  const response = await fetch(`${bastionUrl}${session.rdp_file_url}`, {
    method: "GET",
    headers: {
      authorization: `Bearer ${bastionApiKey}`,
      "User-Agent": getUserAgent(),
    },
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(
      `Failed to download RDP file: ${response.status} ${response.statusText} - ${text}`
    );
  }

  const rdpContent = await response.text();

  const { path: tmpPath } = await tmp.file({
    mode: 0o600,
    prefix: "p0cli-",
    postfix: ".rdp",
  });

  await fs.promises.writeFile(tmpPath, rdpContent, { encoding: "utf-8" });

  if (debug) {
    print2(`RDP file saved to: ${tmpPath}`);
  }

  return tmpPath;
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
      user?: string;
    }
  ) => {
    const { debug } = options;

    if (debug) {
      print2("Creating proxy RDP connection...");
      print2(`Target instance: ${request.permission.resource.instanceId}`);
    }

    const session = await createSession(request, options);

    if (debug) {
      print2(`Session created: ${JSON.stringify(session)}`);
    }

    const rdpFilePath = await downloadRdpFile(request, session, {
      debug,
    });

    print2("Opening RDP session...");
    await openRdpFile(rdpFilePath, { debug });
  },
};
