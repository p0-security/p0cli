/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { getContactMessage } from "../../drivers/config";
import { Authn } from "../../types/identity";
import { SshProvider } from "../../types/ssh";
import { AzureSshKeys, generateAzureSshKeys } from "./keygen";
import {
  AZURE_SUDO_NOT_ALLOWED_PATTERN,
  azureReproBaseCommands,
  azureRequestToSshBase,
  azureSshProviderBase,
} from "./ssh-shared";
import {
  AzureLocalData,
  AzureSshPermissionSpec,
  AzureSshRequest,
} from "./types";

// When connecting through a jump host we fail fast (instead of hanging) if the jump host or the target VM is
// unreachable or not yet ready; the resulting connection error is treated as unprovisioned access below and retried
// within the access propagation window.
export const JUMP_HOST_CONNECT_TIMEOUT_SECONDS = 10;

const unprovisionedAccessPatterns = [
  AZURE_SUDO_NOT_ALLOWED_PATTERN,
  {
    // The host rejected our certificate. Until the access role finishes propagating to the jump host / target VM,
    // public key auth is refused; retry within the propagation window rather than failing immediately.
    pattern: /Permission denied \(publickey\)/,
  },
  {
    // The connection dropped before the SSH banner — e.g. the jump host ProxyCommand exited after a connect timeout,
    // or the host isn't reachable/ready yet. Retry within the propagation window instead of failing hard.
    pattern: /\bConnection closed\b.*\b(?:by UNKNOWN port \d+|by remote host)?/,
  },
] as const;

/** Connects to an Azure VM by SSH-ing through a jump host (a regular VM acting
 * as an SSH bastion) with a `ssh -W` ProxyCommand.
 *
 * Both the jump-host hop and the target hop authenticate with a locally minted
 * key + Azure AD certificate. A new provider is constructed per request so the
 * instance can carry the paths of the keys it generates from `generateKeys`
 * (the single abstraction for creating Azure SSH credentials) to the
 * ProxyCommand that needs them.
 */
export const newAzureJumpHostSshProvider = (): SshProvider<
  AzureSshPermissionSpec,
  AzureLocalData,
  AzureSshRequest
> => {
  /** The key + certificate minted for this provider instance; set by
   * generateKeys and consumed by proxyCommand for the jump-host hop. */
  let keys: AzureSshKeys | undefined;

  const generateKeys = async (
    _authn: Authn,
    request: AzureSshRequest,
    options: { debug?: boolean } = {}
  ) => {
    keys = await generateAzureSshKeys(request, options);
    return keys;
  };

  return {
    ...azureSshProviderBase,

    generateKeys,

    setup: async (_authn, request, options) => {
      const { privateKeyPath, certificatePath, cleanup } =
        await generateAzureSshKeys(request, options);

      return {
        sshOptions: [
          `CertificateFile=${certificatePath}`,

          // Target VMs behind a jump host are ephemeral, and re-used private IPs would trip host key checks, so we
          // disable them. This is ordinarily dangerous, but the connection's integrity is ensured by the authenticated
          // jump host SSH hop.
          "StrictHostKeyChecking=no",
          "UserKnownHostsFile=/dev/null",

          // Fail fast (with a retryable error) instead of hanging when the target VM is offline or not yet reachable
          // through the jump host. ConnectTimeout also bounds the SSH banner exchange when a ProxyCommand is used.
          `ConnectTimeout=${JUMP_HOST_CONNECT_TIMEOUT_SECONDS}`,
        ],
        identityFile: privateKeyPath,
        teardown: cleanup,
      };
    },

    setupProxy: async (authn, request, options) => {
      // ssh-proxy runs in a separate process from ssh-resolve, so the certificate minted there (which authenticates
      // the outer, target hop) isn't available here; mint a fresh one for the jump-host hop.
      const { cleanup } = await generateKeys(authn, request, options);

      return {
        teardown: cleanup,
        // Azure SSH connections only support the default port 22 (enforced by ssh-proxy).
        port: "22",
      };
    },

    // Bound the outer SSH handshake in generated configs so an offline/unreachable target VM surfaces a prompt,
    // retryable error instead of hanging indefinitely (the ProxyCommand below is separately bounded).
    sshConnectTimeoutSeconds: JUMP_HOST_CONNECT_TIMEOUT_SECONDS,

    // Reach the target VM by SSH-ing through the jump host with `-W`. We connect to the target's private IP
    // (request.id) literally rather than using `%h:%p`, so the command works both when embedded as the outer ssh's
    // ProxyCommand (direct `p0 ssh` flow) and when run directly by `p0 ssh-proxy` (native ssh flow).
    proxyCommand: (request, port) => {
      if (!request.jumpHost?.ip) {
        throw "The jump host for this Azure VM has no IP address; cannot establish a connection.";
      }
      if (!keys) {
        throw `SSH keys were not generated before connecting through the jump host. ${getContactMessage()}`;
      }

      const targetPort = port ?? "22";
      return [
        "ssh",
        "-i",
        keys.privateKeyPath,
        "-o",
        `CertificateFile=${keys.certificatePath}`,
        // Avoid any interactive host key prompt, which would hang a non-interactive ProxyCommand.
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        // Fail fast instead of hanging if the jump host is unreachable, and never wait on an auth prompt (stdin is the
        // tunnel here, so a prompt would hang forever). A surfaced error is retried within the propagation window.
        "-o",
        `ConnectTimeout=${JUMP_HOST_CONNECT_TIMEOUT_SECONDS}`,
        "-o",
        "BatchMode=yes",
        "-W",
        `${request.id}:${targetPort}`,
        `${request.linuxUserName}@${request.jumpHost.ip}`,
      ];
    },

    // Jump host connections don't use an Azure Bastion tunnel; the SSH ProxyCommand (appended by the caller) handles
    // reaching the target through the jump host.
    reproCommands: (request, additionalData) =>
      azureReproBaseCommands(request, additionalData),

    requestToSsh: (request) => {
      const base = azureRequestToSshBase(request);

      if (!base.privateIp) {
        throw "This Azure VM has no private IP address; cannot connect through the jump host.";
      }
      if (!base.jumpHost?.ip) {
        throw "The jump host for this Azure VM has no IP address; cannot establish a connection.";
      }

      // Connect to the target VM's private IP through the jump host (see proxyCommand).
      return { ...base, id: base.privateIp };
    },

    unprovisionedAccessPatterns,
  };
};
