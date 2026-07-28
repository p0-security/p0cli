/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { AzureRdpRequest } from "../../../types/rdp";
import { PermissionRequest } from "../../../types/request";
import { azBastionRdpCommand, classifyBastionRdpError } from "../rdp";
import { describe, expect, it } from "vitest";

const REQUEST = {
  permission: {
    bastionHost: {
      id: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/bastionHosts/my-bastion",
      roleId: "role-def-id",
    },
    resource: {
      instanceId:
        "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/my-vm",
      instanceName: "my-vm",
      subscriptionId: "sub-1",
      directoryId: "dir-1",
      region: "eastus",
      networkInterface: { id: "nic-1", subnetId: "subnet-1" },
    },
  },
} as unknown as PermissionRequest<AzureRdpRequest>;

// The bastion host is now identified by a resource ID (`bastionHost.id`),
// matching the SSH bastion/tunnel flow (`az network bastion tunnel --ids
// ...`), rather than the old --name/--resource-group pair the backend no
// longer sends.
describe("azBastionRdpCommand", () => {
  it("identifies the bastion host by --ids and the target VM by --target-resource-id", () => {
    const { command, args } = azBastionRdpCommand(REQUEST, {});

    expect(command).toBe("az");
    expect(args).toEqual(
      expect.arrayContaining([
        "--ids",
        REQUEST.permission.bastionHost.id,
        "--target-resource-id",
        REQUEST.permission.resource.instanceId,
      ])
    );
  });

  it("authenticates with Entra ID (AAD) by default", () => {
    const { args } = azBastionRdpCommand(REQUEST, {});
    expect(args).toEqual(expect.arrayContaining(["--auth-type", "aad"]));
  });

  it("omits --auth-type aad for an admin (local-credential) session", () => {
    const adminRequest = {
      permission: { ...REQUEST.permission, admin: true },
    } as PermissionRequest<AzureRdpRequest>;

    const { args } = azBastionRdpCommand(adminRequest, {});
    expect(args).not.toContain("--auth-type");
    expect(args).not.toContain("aad");
  });

  it("appends --configure and --debug only when requested", () => {
    const bare = azBastionRdpCommand(REQUEST, {});
    expect(bare.args).not.toContain("--configure");
    expect(bare.args).not.toContain("--debug");

    const full = azBastionRdpCommand(REQUEST, {
      configure: true,
      debug: true,
    });
    expect(full.args).toEqual(
      expect.arrayContaining(["--configure", "--debug"])
    );
  });

  // az's --debug output has been observed to include live bearer tokens in
  // cleartext, so it must never be passed unless the user explicitly asked
  // p0 rdp for --debug themselves (CX-Bastion-RDP-500).
  it("never passes --debug to az unless the user passed --debug to p0 rdp", () => {
    expect(azBastionRdpCommand(REQUEST, {}).args).not.toContain("--debug");
    expect(azBastionRdpCommand(REQUEST, { debug: false }).args).not.toContain(
      "--debug"
    );
  });
});

// Without this classifier, a failed `az network bastion rdp` surfaces only
// the generic, code-less "Sub-process exited with code" (exec() in
// util.ts). az prints its own failures at ERROR level regardless of
// --debug, so the classifier works even on a non-debug p0 rdp invocation —
// it just has fewer surrounding DEBUG: lines to filter past when it does.
describe("classifyBastionRdpError", () => {
  it("extracts the actionable line from az's stderr", () => {
    const stderr = [
      "DEBUG: cli.knack.cli: Event: Cli.PreExecute []",
      'DEBUG: urllib3.connectionpool: https://bst-....bastion.azure.com:443 "GET /api/rdpfile?..." 500 None',
      "ERROR: cli.azure.cli.core.azclierror: Request failed with error: Unexpected internal error",
      "ERROR: az_command_data_logger: Request failed with error: Unexpected internal error",
      "INFO: az_command_data_logger: exit code: 1",
    ].join("\n");

    const message = classifyBastionRdpError(stderr);
    expect(message).toContain('"Unexpected internal error"');
    expect(message).toContain("azure-cli/issues/21030");
    expect(message).toContain("--admin");
  });

  it("surfaces a different Bastion service error message plainly, without the known-issue framing", () => {
    const stderr =
      "ERROR: az_command_data_logger: Request failed with error: Target resource not found";
    expect(classifyBastionRdpError(stderr)).toBe(
      "Azure Bastion rejected the RDP request: Target resource not found"
    );
  });

  it("returns undefined when stderr contains no recognizable Bastion service error", () => {
    expect(
      classifyBastionRdpError("DEBUG: some unrelated noise\n")
    ).toBeUndefined();
  });
});
