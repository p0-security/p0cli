/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { isSudoCommand } from "../../commands/shared/ssh";
import { PRIVATE_KEY_PATH } from "../../common/keys";
import { submitPublicKey } from "../../drivers/api";
import { SshProvider } from "../../types/ssh";
import { SelfHostedSshPermissionSpec, SelfHostedSshRequest } from "./types";

const PROPAGATION_TIMEOUT_LIMIT_MS = 2 * 60 * 1000;

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

export const selfHostedSshProvider: SshProvider<
  SelfHostedSshPermissionSpec,
  undefined,
  SelfHostedSshRequest
> = {
  cloudProviderLogin: async () => undefined,
  ensureInstall: async () => {},

  friendlyName: "Warp Portal",

  loginRequiredMessage: "Please login to P0 CLI with 'p0 login'",

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

  generateKeys: async (_) => {
    return {
      privateKeyPath: PRIVATE_KEY_PATH,
    };
  },

  proxyCommand: (request, port) => {
    return ["nc", request.id, port ?? "22"];
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

  async submitPublicKey(authn, request, requestId, publicKey) {
    if (request.generated.publicKey) {
      if (request.generated.publicKey !== publicKey) {
        throw "Public key mismatch. Please revoke the request and try again.";
      }
    } else {
      await submitPublicKey(authn, { publicKey, requestId });
    }
  },
};
