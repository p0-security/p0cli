/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  SsmArgs,
  SsmCommands,
  createInteractiveShellCommand,
  createPortForwardingCommand,
  credsAndInstance,
  startSsmProcesses,
} from ".";
import { SshCommandArgs } from "../../../commands/types";
import { Authn } from "../../../types/identity";
import { Request } from "../../../types/request";
import { AwsSsh } from "../types";

/** Convert an SshCommandArgs into an SSM document "command" parameter */
const commandParameter = (args: SshCommandArgs) =>
  args.command
    ? `${args.command} ${args.arguments
        .map(
          (argument) =>
            // escape all double quotes (") in commands such as `p0 ssh <instance>> echo 'hello; "world"'` because we
            // need to encapsulate command arguments in double quotes as we pass them along to the remote shell
            `"${String(argument).replace(/"/g, '\\"')}"`
        )
        .join(" ")}`.trim()
    : undefined;

const createSsmCommands = (args: Omit<SsmArgs, "requestId">): SsmCommands => {
  const interactiveShellCommand = createInteractiveShellCommand(args);

  const forwardPortAddress = args.forwardPortAddress;
  if (!forwardPortAddress) {
    return { shellCommand: interactiveShellCommand };
  }

  const portForwardingCommand = createPortForwardingCommand({
    ...args,
    forwardPortAddress,
  });

  if (args.noRemoteCommands) {
    return { shellCommand: portForwardingCommand };
  }

  return {
    shellCommand: interactiveShellCommand,
    subCommands: [portForwardingCommand],
  };
};

/** Connect to an SSH backend using AWS Systems Manager (SSM) */
export const ssmSsh = async (
  authn: Authn,
  request: Request<AwsSsh> & {
    id: string;
  },
  args: SshCommandArgs
) => {
  const { credential, region, instance } = await credsAndInstance(
    authn,
    request
  );

  const ssmArgs = {
    instance: instance!,
    region: region!,
    documentName: request.generated.documentName,
    requestId: request.id,
    forwardPortAddress: args.L,
    noRemoteCommands: args.N,
    command: commandParameter(args),
  };

  const ssmCommands = createSsmCommands(ssmArgs);

  await startSsmProcesses(credential, ssmCommands);
};
