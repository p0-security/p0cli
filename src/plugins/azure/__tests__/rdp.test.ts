/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../../drivers/stdio";
import { AzureRdpRequest } from "../../../types/rdp";
import { PermissionRequest } from "../../../types/request";
import { exec } from "../../../util";
import {
  azBastionRdpCommand,
  azureRdpProvider,
  classifyBastionRdpError,
  sanitizeAzureDebugOutput,
} from "../rdp";
import { describe, expect, it, vi } from "vitest";

vi.mock("../../../drivers/stdio", () => ({
  print2: vi.fn(),
}));

// Spread the original so the real osSafeCommand (used by azBastionRdpCommand)
// keeps working; only stub the subprocess execution.
vi.mock("../../../util", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../util")>()),
  exec: vi.fn(),
}));

const mockExec = vi.mocked(exec);
const mockPrint2 = vi.mocked(print2);

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

// az's --debug output has been observed to include live bearer tokens in
// cleartext on DEBUG-level lines. Even when the user explicitly asked p0 rdp
// for --debug, that raw stderr must never be echoed to the terminal as-is.
const MOCK_BEARER_TOKEN =
  "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

describe("sanitizeAzureDebugOutput", () => {
  it("redacts a bearer token even on an ERROR line", () => {
    const stderr = `ERROR: cli.azure.cli.core.azclierror: Response ${MOCK_BEARER_TOKEN}`;
    const sanitized = sanitizeAzureDebugOutput(stderr);
    expect(sanitized).not.toContain(MOCK_BEARER_TOKEN);
    expect(sanitized).toContain("[REDACTED]");
  });

  it("drops DEBUG/INFO lines (where az's bearer tokens are actually logged), keeping ERROR/WARNING context", () => {
    const stderr = [
      "DEBUG: cli.knack.cli: Event: Cli.PreExecute []",
      `DEBUG: urllib3.connectionpool: Response ${MOCK_BEARER_TOKEN}`,
      "ERROR: az_command_data_logger: Request failed with error: Unexpected internal error",
      "INFO: az_command_data_logger: exit code: 1",
    ].join("\n");

    const sanitized = sanitizeAzureDebugOutput(stderr);
    expect(sanitized).not.toContain(MOCK_BEARER_TOKEN);
    expect(sanitized).not.toContain("DEBUG:");
    expect(sanitized).not.toContain("INFO:");
    expect(sanitized).toContain(
      "ERROR: az_command_data_logger: Request failed with error: Unexpected internal error"
    );
  });
});

describe("azureRdpProvider.spawnConnection debug logging", () => {
  it("never prints a raw bearer token to the terminal, even with --debug on a failed connection", async () => {
    mockExec.mockRejectedValueOnce(
      Object.assign(new Error("Sub-process exited with code"), {
        code: 1,
        stdout: "",
        stderr: [
          "DEBUG: cli.knack.cli: Event: Cli.PreExecute []",
          `DEBUG: urllib3.connectionpool: Response ${MOCK_BEARER_TOKEN}`,
          "ERROR: az_command_data_logger: Request failed with error: Unexpected internal error",
        ].join("\n"),
      })
    );

    await expect(
      azureRdpProvider.spawnConnection(REQUEST, { debug: true })
    ).rejects.toThrow();

    const printedText = mockPrint2.mock.calls.map((call) => call[0]).join("\n");
    expect(printedText).not.toContain(MOCK_BEARER_TOKEN);
  });
});
