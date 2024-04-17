/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

/** Connect to an SSH backend using AWS Systems Manager (SSM) for copying local files to remote */
import {
  SsmArgs,
  SsmCommands,
  createInteractiveShellCommand,
  createPortForwardingCommand,
  credsAndInstance,
  startSsmProcesses,
} from ".";
import { ScpCommandArgs } from "../../../commands/types";
import { Authn } from "../../../types/identity";
import { Request } from "../../../types/request";
import { AwsSsh } from "../types";
import { waitForLocalPortAndWriteFile } from "./net";

const DEFAULT_PORT = "28657";

/** An explicit local pattern decidedly marks a path as local. Begins with /, ., or .. followed by any characters */
const EXPLICIT_LOCAL_PATTERN = /^(\/|\.\/|\.\.\/).*$/;

/** If a path is not explicitly local, use this pattern to determine if it's remote */
const REMOTE_PATTERN_COLON = /^([^:]+:)(.*)$/; // Matches host:[path]

/** Secondary pattern to to determine whether the path is remote */
const REMOTE_PATTERN_URI = /^scp:\/\/([^:/]+)(:[0-9]*)?(\/?.*)?$/; // Matches scp://host[:port][/path]

const createSsmCommands = (
  args: Omit<SsmArgs, "requestId"> &
    Required<Pick<SsmArgs, "forwardPortAddress">>
): SsmCommands => {
  return {
    subCommands: [
      createInteractiveShellCommand(args),
      createPortForwardingCommand(args),
    ],
  };
};

type PathType =
  | {
      type: "local";
      path: string;
    }
  | {
      type: "remote";
      host: string;
      path: string;
      port?: string;
    };

const rightTrim = (end: string, str?: string) => {
  if (str === undefined) return str;
  if (str.endsWith(end)) {
    return str.slice(0, -end.length);
  }
  return str;
};

const leftTrim = (start: string, str?: string) => {
  if (str === undefined) return str;
  if (str.startsWith(start)) {
    return str.slice(start.length);
  }
  return str;
};

export const isExplicitlyLocal = (path: string) =>
  EXPLICIT_LOCAL_PATTERN.test(path);

export const isRemoteWithColon = (path: string) => {
  if (path.startsWith("scp://")) {
    return {
      isMatch: false,
    };
  }
  const match = path.match(REMOTE_PATTERN_COLON);
  if (match !== null && match[1] !== undefined && match[2] !== undefined) {
    return {
      isMatch: true,
      host: match[1],
      path: match[2],
    };
  }
  return {
    isMatch: false,
  };
};

export const isRemoteWithUri = (path: string) => {
  const match = path.match(REMOTE_PATTERN_URI);
  // match[2] and match[3] can be undefined
  if (match && match[1] !== undefined) {
    return {
      isMatch: true,
      host: match[1],
      port: match[2] || "",
      path: match[3] || "",
    };
  }
  return {
    isMatch: false,
  };
};

export const detectPathType = (path: string): PathType => {
  if (isExplicitlyLocal(path)) {
    return {
      type: "local",
      path,
    };
  }
  const remoteWithColon = isRemoteWithColon(path);
  if (remoteWithColon.isMatch) {
    return {
      type: "remote",
      host: rightTrim(":", remoteWithColon.host) || "",
      path: remoteWithColon.path || "",
    };
  }
  const remoteWithUri = isRemoteWithUri(path);
  if (remoteWithUri.isMatch) {
    return {
      type: "remote",
      host: remoteWithUri.host || "",
      port: leftTrim(":", remoteWithUri.port),
      path: remoteWithUri.path || "",
    };
  }
  return {
    type: "local",
    path,
  };
};

export const ssmScpLocalToRemote = async (
  authn: Authn,
  request: Request<AwsSsh> & {
    id: string;
  },
  args: ScpCommandArgs,
  sourcePath: Extract<PathType, { type: "local" }>,
  destinationPath: Extract<PathType, { type: "remote" }>
) => {
  const port = args.port || destinationPath.port || DEFAULT_PORT;
  args.destination = destinationPath.host;

  const { credential, region, instance } = await credsAndInstance(
    authn,
    request
  );

  const ssmArgs = {
    instance: instance!,
    region: region!,
    documentName: request.generated.documentName,
    requestId: request.id,
    forwardPortAddress: `${port}:${port}`,
    // The netcat utility must be installed on the remote for this to work.
    // In non-debian-based systems that have bash we could use the /dev/tcp file descriptor that bash creates.
    // `-l` Used to specify that nc should listen for an incoming connection rather than initiate a connection to a remote host
    // `-p` Specifies the source port nc should use, subject to privilege restrictions and availability
    command: `nc -l -p ${port} > ${destinationPath.path}`,
  };

  const ssmCommands = createSsmCommands(ssmArgs);

  await Promise.all([
    startSsmProcesses(credential, ssmCommands),
    // Note: instead of waiting we could capture when the port is open
    // and only then write the file. That would require changing how startSsmProcesses works.
    waitForLocalPortAndWriteFile({
      fileToSend: sourcePath.path,
      port,
    }),
  ]);
};
