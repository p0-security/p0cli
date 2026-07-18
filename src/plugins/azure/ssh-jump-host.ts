/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { getContactMessage } from "../../drivers/config";
import { SshProvider } from "../../types/ssh";
import { createTempDirectoryForKeys } from "../ssh/shared";
import { azSetSubscription } from "./auth";
import {
  AD_CERT_FILENAME,
  AD_SSH_KEY_PRIVATE,
  azureSshLoginReproCommands,
  azureSshProviderBase,
  generateSshKeyAndAzureAdCert,
} from "./ssh-shared";
import {
  AzureLocalData,
  AzureSshPermissionSpec,
  AzureSshRequest,
} from "./types";
import path from "node:path";

// When connecting through a jump host we fail fast (instead of hanging) if the jump host or the target VM is
// unreachable or not yet ready; the resulting connection error is treated as unprovisioned access below and retried
// within the access propagation window.
export const JUMP_HOST_CONNECT_TIMEOUT_SECONDS = 20;

// The outer (target) hop's ConnectTimeout also bounds its own SSH banner exchange when a ProxyCommand is used, and
// that exchange only starts once the inner jump-host hop has finished connecting *and* authenticating. Since both
// hops' ConnectTimeout clocks start at essentially the same instant, an outer timeout equal to the inner one would
// leave no time for the outer's own banner exchange whenever the jump-host hop uses any meaningful fraction of its
// budget — exactly what happens while access is still propagating. Give the outer hop extra headroom.
export const TARGET_CONNECT_TIMEOUT_SECONDS =
  JUMP_HOST_CONNECT_TIMEOUT_SECONDS + 10;

/** The inner (ProxyCommand) ssh's error when the TCP connection to the jump
 * host itself cannot be established (offline, still booting, or filtered). */
const JUMP_HOST_CONNECT_FAILED_PATTERN =
  /ssh: connect to host (\S+) port \d+: (?:Connection timed out|Operation timed out|Connection refused|No route to host)/;

/** The jump host was reached, but its `-W` forward to the target VM failed. */
const TARGET_CONNECT_FAILED_PATTERN =
  /channel \d+: open failed: connect (?:timeout|failed)/;

const jumpHostUnprovisionedAccessPatterns = [
  {
    // The host rejected our certificate. Until the access role finishes propagating to the jump host / target VM,
    // public key auth is refused; retry within the propagation window rather than failing immediately.
    // sshd lists every auth method it allows, so a host that also permits password auth
    // reports "(publickey,password)" — tolerate any method list that includes publickey.
    pattern: /Permission denied \([^)]*publickey[^)]*\)/,
  },
  {
    // The connection dropped before the SSH banner — e.g. the jump host ProxyCommand exited after a connect timeout,
    // or the host isn't reachable/ready yet. Retry within the propagation window instead of failing hard.
    pattern: /\bConnection closed\b.*\b(?:by UNKNOWN port \d+|by remote host)?/,
  },
  {
    // The outer hop's own ConnectTimeout expired before the target's banner arrived (reported against "UNKNOWN"
    // since the connection is piped through a ProxyCommand rather than a real socket) — typically because the inner
    // jump-host hop used up most of the shared propagation-window budget. Retry rather than failing hard.
    pattern:
      /Connection (?:timed out during banner exchange|to UNKNOWN port \d+ timed out)/,
  },
] as const;

/** Mints a fresh key + Azure AD certificate for the jump-host hop. The caller
 * owns `cleanup`, and is responsible for passing the returned paths along to
 * proxyCommand (e.g. via the setup/setupProxy return value) — this provider
 * holds no state of its own. */
const mintKeys = async (
  request: AzureSshRequest,
  options: { debug?: boolean } = {}
) => {
  // The subscription ID here is used to ensure that the user is logged in to the correct tenant/directory.
  // As long as a subscription ID in the correct tenant is provided, this will work; it need not be the same
  // subscription as which contains the jump host or the target VM.
  const linuxUserName = await azSetSubscription(request, options);

  if (linuxUserName !== request.linuxUserName) {
    throw `Azure CLI login returned a different user name than expected. Expected: ${request.linuxUserName}, Actual: ${linuxUserName}`;
  }

  const { path: keyPath, cleanup } = await createTempDirectoryForKeys();

  try {
    await generateSshKeyAndAzureAdCert(keyPath, options);
  } catch (error: any) {
    await cleanup();
    throw error;
  }

  return {
    privateKeyPath: path.join(keyPath, AD_SSH_KEY_PRIVATE),
    certificatePath: path.join(keyPath, AD_CERT_FILENAME),
    cleanup,
  };
};

/** Connects to an Azure VM by SSH-ing through a jump host (a regular VM acting
 * as an SSH bastion) with a `ssh -W` ProxyCommand.
 *
 * Both the jump-host hop and the target hop authenticate with a locally minted
 * key + Azure AD certificate. Like every other provider, this is a stateless
 * singleton: the keys minted by setup/setupProxy are threaded to proxyCommand
 * as an explicit argument rather than held on the provider instance.
 */
export const azureJumpHostSshProvider: SshProvider<
  AzureSshPermissionSpec,
  AzureLocalData,
  AzureSshRequest
> = {
  ...azureSshProviderBase,

  setup: async (_authn, request, options) => {
    // Both hops authenticate with the same key + certificate: the outer (target) hop reads it from
    // identityFile/sshOptions below, and the embedded ProxyCommand reads it from the setup data (see proxyCommand).
    const { privateKeyPath, certificatePath, cleanup } = await mintKeys(
      request,
      options
    );

    return {
      sshOptions: [
        `CertificateFile=${certificatePath}`,

        // Target VMs behind a jump host are ephemeral, and re-used private IPs would trip host key checks, so we
        // disable them. This is ordinarily dangerous, but the connection's integrity is ensured by the authenticated
        // jump host SSH hop.
        "StrictHostKeyChecking=no",
        "UserKnownHostsFile=/dev/null",

        // Fail fast (with a retryable error) instead of hanging when the target VM is offline or not yet reachable
        // through the jump host. ConnectTimeout also bounds the SSH banner exchange when a ProxyCommand is used, so
        // this must exceed the inner jump-host hop's own ConnectTimeout (see TARGET_CONNECT_TIMEOUT_SECONDS above).
        `ConnectTimeout=${TARGET_CONNECT_TIMEOUT_SECONDS}`,
      ],
      identityFile: privateKeyPath,
      certificatePath,
      teardown: cleanup,
    };
  },

  setupProxy: async (request, options) => {
    // ssh-proxy runs in a separate process from ssh-resolve, so the certificate minted there (which authenticates
    // the outer, target hop) isn't available here; mint a fresh one for the jump-host hop.
    const { privateKeyPath, certificatePath, cleanup } = await mintKeys(
      request,
      options
    );

    return {
      teardown: cleanup,
      // Azure SSH connections only support the default port 22 (enforced by ssh-proxy).
      port: "22",
      identityFile: privateKeyPath,
      certificatePath,
    };
  },

  // Bound the outer SSH handshake in generated configs so an offline/unreachable target VM surfaces a prompt,
  // retryable error instead of hanging indefinitely (the ProxyCommand below is separately bounded). Must exceed
  // JUMP_HOST_CONNECT_TIMEOUT_SECONDS — see TARGET_CONNECT_TIMEOUT_SECONDS above.
  sshConnectTimeoutSeconds: TARGET_CONNECT_TIMEOUT_SECONDS,

  // Reach the target VM by SSH-ing through the jump host with `-W`. We connect to the target's private IP
  // (request.id) literally rather than using `%h:%p`, so the command works both when embedded as the outer ssh's
  // ProxyCommand (direct `p0 ssh` flow) and when run directly by `p0 ssh-proxy` (native ssh flow). `credentials` is
  // the identityFile/certificatePath minted by setup/setupProxy above, passed in by the caller.
  proxyCommand: (request, port, credentials) => {
    if (!request.jumpHost?.publicIp) {
      throw "The jump host for this Azure VM has no IP address; cannot establish a connection.";
    }
    if (!credentials?.identityFile || !credentials?.certificatePath) {
      throw `SSH keys were not generated before connecting through the jump host. ${getContactMessage()}`;
    }

    const targetPort = port ?? "22";
    return [
      "ssh",
      // Unlike the outer hop (which always sets its own -o ProxyCommand, so it can't be redirected by a config
      // file — command-line -o options take precedence over anything in ssh_config), this inner hop sets no
      // ProxyCommand of its own. If the user's ~/.ssh/config has a `Match exec` hook delegating to `p0 ssh-resolve`
      // (the documented native-ssh integration), this ssh invocation would otherwise re-trigger it for the jump
      // host's IP, and any ProxyCommand that resolution supplies *would* apply here — recursing if it resolves to
      // another jump-host hop. This hop is already fully self-parameterized, so skip the user's config entirely.
      "-F",
      "/dev/null",
      "-i",
      credentials.identityFile,
      "-o",
      `CertificateFile=${credentials.certificatePath}`,
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
      `${request.linuxUserName}@${request.jumpHost.publicIp}`,
    ];
  },

  // Jump host connections don't use an Azure Bastion tunnel; the SSH ProxyCommand (appended by the caller) handles
  // reaching the target through the jump host.
  reproCommands: (request, additionalData) =>
    azureSshLoginReproCommands(request, additionalData),

  requestToSsh: (request) => {
    const { jumpHost, resource } = request.permission;
    const privateIp = resource.networkInterface.privateIp;

    if (!privateIp) {
      throw "This Azure VM has no private IP address; cannot connect through the jump host.";
    }
    if (!jumpHost?.publicIp) {
      throw "The jump host for this Azure VM has no IP address; cannot establish a connection.";
    }

    return {
      type: "azure",
      // Connect to the target VM's private IP through the jump host (see proxyCommand).
      id: privateIp,
      ...request.cliLocalData,
      instanceId: resource.instanceId,
      subscriptionId: resource.subscriptionId,
      instanceResourceGroup: resource.resourceGroupId,
      directoryId: request.generated.directoryId,
      jumpHost,
      privateIp,
    };
  },

  // The ConnectTimeouts above make an offline jump host / target VM fail fast on each attempt, but such a failure is
  // indistinguishable from access still propagating, so it is retried until the propagation window expires. At that
  // point the generic "access did not propagate" error would misattribute the cause; classify it instead. The
  // messages never claim certainty: a connect timeout can also be a network path issue (e.g. a firewall).
  connectionErrorMessage: (stderr, request) => {
    const jumpHostIp = request.jumpHost?.publicIp;
    const jumpHostConnect = stderr.match(JUMP_HOST_CONNECT_FAILED_PATTERN);
    if (jumpHostConnect && jumpHostIp && jumpHostConnect[1] === jumpHostIp) {
      return (
        `\nCould not connect to the jump host for this instance (${jumpHostIp}). ` +
        `The jump host may be offline, still starting up, or unreachable from your network. ` +
        `Verify that the jump host VM is running, then retry.`
      );
    }
    if (TARGET_CONNECT_FAILED_PATTERN.test(stderr)) {
      return (
        `\nConnected to the jump host, but it could not reach the target VM (${request.id}). ` +
        `The VM may be offline or not yet accepting SSH connections. ` +
        `Verify that the VM is running, then retry.`
      );
    }
    return undefined;
  },

  unprovisionedAccessPatterns: [
    ...azureSshProviderBase.unprovisionedAccessPatterns,
    ...jumpHostUnprovisionedAccessPatterns,
  ],
};
