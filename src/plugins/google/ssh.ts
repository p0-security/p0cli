/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { isSudoCommand } from "../../commands/shared/ssh";
import { SshProvider } from "../../types/ssh";
import { importSshKey } from "./ssh-key";
import { GcpSshPermissionSpec, GcpSshRequest } from "./types";

/** Maximum number of attempts to start an SSH session
 *
 * The length of each attempt varies based on the type of error from a few seconds to < 1s
 */
const MAX_SSH_RETRIES = 120;

export const gcpSshProvider: SshProvider<
  GcpSshPermissionSpec,
  { linuxUserName: string },
  GcpSshRequest
> = {
  requestToSsh: (request) => {
    return {
      id: request.permission.spec.instanceName,
      projectId: request.permission.spec.projectId,
      zone: request.permission.spec.zone,
      linuxUserName: request.cliLocalData.linuxUserName,
      type: "gcloud",
    };
  },
  toCliRequest: async (request, options) => ({
    ...request,
    cliLocalData: {
      linuxUserName: await importSshKey(
        request.permission.spec.publicKey,
        options
      ),
    },
  }),
  cloudProviderLogin: async () => undefined, // TODO @ENG-2284 support login with Google Cloud
  proxyCommand: (request) => {
    return [
      "gcloud",
      "compute",
      "start-iap-tunnel",
      request.id,
      "%p",
      // --listen-on-stdin flag is required for interactive SSH session.
      // It is undocumented on page https://cloud.google.com/sdk/gcloud/reference/compute/start-iap-tunnel
      // but mention on page https://cloud.google.com/iap/docs/tcp-by-host
      // and also found in `gcloud ssh --dry-run` output
      "--listen-on-stdin",
      `--zone=${request.zone}`,
      `--project=${request.projectId}`,
    ];
  },
  reproCommands: () => undefined, // TODO @ENG-2284 support login with Google Cloud
  preTestAccessPropagationArgs: (cmdArgs) => {
    if (isSudoCommand(cmdArgs)) {
      return {
        ...cmdArgs,
        // `sudo -v` prints `Sorry, user <user> may not run sudo on <hostname>.` to stderr when user is not a sudoer.
        // It prints nothing to stdout when user is a sudoer - which is important because we don't want any output from the pre-test.
        command: "sudo",
        arguments: ["-v"],
      };
    }
    return undefined;
  },
  maxRetries: MAX_SSH_RETRIES,
  friendlyName: "Google Cloud",
};
