/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { AzureRdpRequest } from "../../types/rdp";
import { PermissionRequest } from "../../types/request";
import { exec, osSafeCommand } from "../../util";
import { azSetSubscription } from "./auth";

export const azBastionRdpCommand = (
  request: PermissionRequest<AzureRdpRequest>,
  options: { configure?: boolean; debug?: boolean }
) => {
  const { configure, debug } = options;
  const { admin, bastionHost, resource } = request.permission;
  return osSafeCommand("az", [
    "network",
    "bastion",
    "rdp",
    "--ids",
    bastionHost.id,
    "--target-resource-id",
    resource.instanceId,
    // Entra ID (AAD) auth is only for the target VM's AAD-joined identity.
    // Admin sessions connect with the VM's local administrator credentials
    // instead, so --auth-type aad must be omitted (the native RDP client
    // then prompts for local credentials, same as connecting outside
    // Bastion). TODO: verify against az CLI behavior once available —
    // `az network bastion rdp --auth-type` doesn't document its accepted
    // values the way `bastion ssh --auth-type` does (password/ssh-key/AAD).
    ...(admin ? [] : ["--auth-type", "aad"]),
    ...(configure ? ["--configure"] : []),
    // Only pass --debug to az when the user asked p0 rdp for --debug. az's
    // --debug output has included live bearer tokens in cleartext (a real
    // `Response eyJ...` access token was observed in one capture) — capturing
    // that into `error.stderr` on every attempt, not just when the user
    // opted into verbose output, would be a real secret-exposure risk.
    // Unnecessary too: classifyBastionRdpError below only needs the
    // `ERROR: ...` lines az prints on failure regardless of --debug — only
    // the DEBUG: lines (and the token) are gated behind it.
    ...(debug ? ["--debug"] : []),
  ]);
};

/** Matches the one actionable line the Azure Bastion CLI extension raises
 * when the Bastion *service* itself rejects the request
 * (azext_bastion/custom.py: handle_error_response). az prints this at ERROR
 * level, so it's present in stderr regardless of --debug. Surfacing just
 * this turns an opaque failure into an actionable one — the raw thrown error
 * otherwise only ever says the generic, code-less "Sub-process exited with
 * code" (see exec() in util.ts, whose Error message never interpolates the
 * actual exit code). */
const BASTION_SERVICE_ERROR_PATTERN = /Request failed with error: (.+)/;

/** A known, longstanding Azure Bastion service-side failure generating an
 * RDP file for an AAD-authenticated (--auth-type aad / enablerdsaad=true)
 * session. Reported upstream with no confirmed root cause or fix:
 * https://github.com/Azure/azure-cli/issues/21030
 * https://github.com/Azure/azure-cli/issues/28148
 * Not something p0 can resolve client-side. */
const BASTION_UNEXPECTED_INTERNAL_ERROR = "Unexpected internal error";

export const classifyBastionRdpError = (stderr: string): string | undefined => {
  const match = stderr.match(BASTION_SERVICE_ERROR_PATTERN);
  if (!match?.[1]) return undefined;
  const message = match[1].trim();

  if (message === BASTION_UNEXPECTED_INTERNAL_ERROR) {
    return (
      `Azure Bastion rejected the RDP request with "${message}". This is a known, longstanding Azure ` +
      `Bastion service-side failure when generating an AAD-authenticated RDP session ` +
      `(see github.com/Azure/azure-cli/issues/21030 and /issues/28148) — it is not something p0 can fix ` +
      `client-side. Try again in a few minutes, retry with --admin to connect with the VM's local ` +
      `credentials instead of Entra ID, or ask your Azure admin to verify the Bastion host's and target ` +
      `VM's Entra ID sign-in configuration.`
    );
  }

  return `Azure Bastion rejected the RDP request: ${message}`;
};

export const azureRdpProvider = {
  setup: async (
    request: PermissionRequest<AzureRdpRequest>,
    options: { debug?: boolean }
  ) => {
    const entraIdUserEmail = await azSetSubscription(
      request.permission.resource,
      options
    );
    return { entraIdUserEmail };
  },

  spawnConnection: async (
    request: PermissionRequest<AzureRdpRequest>,
    options: {
      configure?: boolean;
      debug?: boolean;
    }
  ) => {
    const { debug } = options;

    if (debug) {
      print2("Creating Azure Bastion RDP connection...");
    }

    try {
      const { command, args } = azBastionRdpCommand(request, options);

      if (debug) {
        print2(`Executing: ${command} ${args.join(" ")}`);
      }

      await exec(command, args, { check: true });
    } catch (error: any) {
      const stderr: string | undefined = error?.stderr;
      const classified = stderr && classifyBastionRdpError(stderr);

      if (debug) {
        print2(
          `Azure Bastion RDP command failed (exit code ${error?.code ?? "unknown"}).`
        );
        if (stderr) {
          print2("Error details:");
          print2(stderr);
        }
      }

      throw new Error(
        `Failed to create Azure Bastion RDP connection: ${classified ?? error?.message ?? String(error)}`
      );
    }
  },
};
