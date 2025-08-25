/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { isSudoCommand } from "../../commands/shared/ssh";
import { PRIVATE_KEY_PATH } from "../../common/keys";
import { SshProvider } from "../../types/ssh";
import { ensureGcpSshInstall } from "./install";
import { importSshKey } from "./ssh-key";
import { GcpSshPermissionSpec, GcpSshRequest } from "./types";

// It typically takes < 1 minute for access to propagate on GCP, so set the time limit to 2 minutes.
const PROPAGATION_TIMEOUT_LIMIT_MS = 2 * 60 * 1000;

/**
 * There are 7 cases of unprovisioned access in Google Cloud.
 * These are all potentially subject to propagation delays.
 * 1. The linux user name is not present in the user's Google Workspace profile `posixAccounts` attribute
 * 2. The public key is not present in the user's Google Workspace profile `sshPublicKeys` attribute
 * 3. The user cannot act as the service account of the compute instance
 * 4. The user cannot tunnel through the IAP tunnel to the instance
 * 5. The user doesn't have osLogin or osAdminLogin role to the instance
 * 5.a. compute.instances.get permission is missing
 * 5.b. compute.instances.osLogin permission is missing
 * 6. compute.instances.osAdminLogin is not provisioned but compute.instances.osLogin is - happens when a user upgrades existing access to sudo
 * 7: Rare occurrence, the exact conditions so far undetermined (together with CONNECTION_CLOSED_MESSAGE)
 *
 * 1, 2, 3 (yes!), 5b: result in PUBLIC_KEY_DENIED_MESSAGE
 * 4: results in UNAUTHORIZED_TUNNEL_USER_MESSAGE and also CONNECTION_CLOSED_MESSAGE
 * 5a: results in UNAUTHORIZED_INSTANCES_GET_MESSAGE
 * 6: results in SUDO_MESSAGE
 * 7: results in DESTINATION_READ_ERROR and also CONNECTION_CLOSED_MESSAGE
 */
const unprovisionedAccessPatterns = [
  { pattern: /Permission denied \(publickey\)/ },
  {
    // The output of `sudo -v` when the user is not allowed to run sudo
    pattern: /Sorry, user .+ may not run sudo on .+/,
  },
  { pattern: /Error while connecting \[4033: 'not authorized'\]/ },
  {
    pattern: /Required 'compute\.instances\.get' permission/,
    validationWindowMs: 30e3,
  },
  { pattern: /Error while connecting \[4010: 'destination read failed'\]/ },
] as const;

export const gcpSshProvider: SshProvider<
  GcpSshPermissionSpec,
  { linuxUserName: string },
  GcpSshRequest
> = {
  // TODO support login with Google Cloud
  cloudProviderLogin: async () => undefined,

  ensureInstall: async () => {
    if (!(await ensureGcpSshInstall())) {
      throw "Please try again after installing the required GCP utilities";
    }
  },

  friendlyName: "Google Cloud",

  loginRequiredMessage:
    "Please login to Google Cloud CLI with 'gcloud auth login'",

  loginRequiredPattern: /You do not currently have an active account selected/,

  propagationTimeoutMs: PROPAGATION_TIMEOUT_LIMIT_MS,

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

  generateKeys: async (_authn, request) => {
    return {
      username: request.linuxUserName,
      privateKeyPath: PRIVATE_KEY_PATH,
    };
  },

  proxyCommand: (request, port) => {
    return [
      "gcloud",
      "compute",
      "start-iap-tunnel",
      request.id,
      port ? port : "%p",
      // --listen-on-stdin flag is required for interactive SSH session.
      // It is undocumented on page https://cloud.google.com/sdk/gcloud/reference/compute/start-iap-tunnel
      // but mention on page https://cloud.google.com/iap/docs/tcp-by-host
      // and also found in `gcloud ssh --dry-run` output
      "--listen-on-stdin",
      `--zone=${request.zone}`,
      `--project=${request.projectId}`,
    ];
  },

  reproCommands: () => undefined,

  requestToSsh: (request) => {
    return {
      id: request.permission.resource.instanceName,
      projectId: request.permission.resource.projectId,
      zone: request.permission.zone,
      linuxUserName: request.cliLocalData.linuxUserName,
      type: "gcloud",
    };
  },

  unprovisionedAccessPatterns,

  toCliRequest: async (request, options) => ({
    ...request,
    cliLocalData: {
      linuxUserName: await importSshKey(request.permission.publicKey, options),
    },
  }),
};
