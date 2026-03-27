/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { isSudoCommand } from "../../commands/shared/ssh";
import { fetchIntegrationConfig, submitPublicKey } from "../../drivers/api";
import { SshConfig } from "../../plugins/ssh/types";
import { SshProvider } from "../../types/ssh";
import { getAppName, getOperatingSystem } from "../../util";
import { signWithKms } from "./kms";
import { SelfHostedSshPermissionSpec, SelfHostedSshRequest } from "./types";

const PROPAGATION_TIMEOUT_LIMIT_MS = 2 * 60 * 1000;

const unprovisionedAccessPatterns = [
  { pattern: /Permission denied \(publickey\)/ },
  {
    // The output of `sudo -v` when the user is not allowed to run sudo
    pattern: /Sorry, user .+ may not run sudo on .+/,
  },
  {
    pattern: /\bConnection closed\b.*\b(?:by UNKNOWN port \d+|by remote host)?/,
  },
] as const;

export const selfHostedSshProvider: SshProvider<
  SelfHostedSshPermissionSpec,
  undefined,
  SelfHostedSshRequest
> = {
  cloudProviderLogin: async () => undefined,
  ensureInstall: async () => {},

  friendlyName: "Self-hosted",

  get loginRequiredMessage() {
    return `Please login with '${getAppName()} login'`;
  },

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

  async submitPublicKey(authn, _request, requestId, publicKey, debug) {
    const configDoc = await fetchIntegrationConfig<{ config: SshConfig }>(
      authn,
      "ssh",
      debug
    );
    const kmsKeyResourceName = configDoc?.config?.kmsKeyResourceName;

    let signature: string | undefined;
    if (kmsKeyResourceName) {
      const projectId = kmsKeyResourceName.split("/").at(1);
      if (!projectId) {
        throw `Invalid KMS key resource name: ${kmsKeyResourceName}`;
      }
      type GcloudIamWriteItem = { defaultPool?: string; state: string };
      type GcloudConfig = { "iam-write": Record<string, GcloudIamWriteItem> };
      const gcloudConfigDoc = await fetchIntegrationConfig<{
        config: GcloudConfig;
      }>(authn, "gcloud", debug);
      const wifPool =
        gcloudConfigDoc?.config?.["iam-write"]?.[projectId]?.defaultPool;
      if (!wifPool) {
        throw `No WIF pool configured for GCP project ${projectId}. Ensure 'defaultPool' is set in the gcloud iam-write integration.`;
      }
      signature = await signWithKms(
        publicKey,
        kmsKeyResourceName,
        authn.identity,
        wifPool,
        { debug }
      );
    }

    await submitPublicKey(authn, { publicKey, requestId, signature }, debug);
  },

  proxyCommand: (request, port) => {
    const targetPort = port ?? "22";
    // On Windows, use ncat (from nmap). On Unix/Mac, use nc.
    // Both have the same command line syntax: command localhost port
    const command = getOperatingSystem() === "win" ? "ncat" : "nc";
    return [command, request.id, targetPort];
  },

  reproCommands: () => undefined,

  requestToSsh: (request) => {
    return {
      id: request.permission.resource.publicIp,
      linuxUserName: request.generated.linuxUserName,
      type: "self-hosted",
    };
  },

  unprovisionedAccessPatterns,

  toCliRequest: async (request) => ({ ...request, cliLocalData: undefined }),
};
