/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { azureSshProvider } from "../ssh";
import { AzureSsh } from "../types";
import { describe, expect, it } from "vitest";

const BASTION_ID =
  "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/bastionHosts/bastion-1";

const makeRequest = (permissionOverrides: object): AzureSsh =>
  ({
    cliLocalData: { linuxUserName: "alice" },
    generated: { directoryId: "dir-1", linuxUserName: "alice" },
    permission: {
      provider: "azure",
      destination: "vm-1",
      resource: {
        instanceId:
          "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1",
        instanceName: "vm-1",
        subscriptionName: "sub-1-name",
        resourceGroupId: "rg-1",
        subscriptionId: "sub-1",
        region: "eastus",
        networkInterfaceIds: [],
      },
      ...permissionOverrides,
    },
  }) as unknown as AzureSsh;

describe("requestToSsh", () => {
  it("reads the bastion host ID from permission.bastionHost.id", () => {
    const request = makeRequest({
      bastionHost: { id: BASTION_ID, roleId: "role-1" },
    });

    expect(azureSshProvider.requestToSsh(request).bastionId).toBe(BASTION_ID);
  });

  it("falls back to the legacy permission.bastionHostId field", () => {
    const request = makeRequest({ bastionHostId: BASTION_ID });

    expect(azureSshProvider.requestToSsh(request).bastionId).toBe(BASTION_ID);
  });

  it("prefers bastionHost.id over the legacy field when both are present", () => {
    const request = makeRequest({
      bastionHost: { id: BASTION_ID, roleId: "role-1" },
      bastionHostId: "/legacy/bastion/id",
    });

    expect(azureSshProvider.requestToSsh(request).bastionId).toBe(BASTION_ID);
  });

  it("throws a clear error when no bastion host is present", () => {
    const request = makeRequest({});

    expect(() => azureSshProvider.requestToSsh(request)).toThrow(
      /bastion host/i
    );
  });
});
