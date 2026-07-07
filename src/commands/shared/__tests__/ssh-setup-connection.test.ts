/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Authn } from "../../../types/identity";
import { PermissionRequest } from "../../../types/request";
import { PluginSshRequest } from "../../../types/ssh";
import { BaseSshCommandArgs, setupSshConnection } from "../ssh";
import { beforeEach, describe, expect, it, vi } from "vitest";
import yargs from "yargs";

// setupSshConnection resolves its provider through newSshProvider at call
// time, which for an "aws" request returns the aws plugin's provider — so mock
// that module. Vitest resolves the export at property-access time, so tests
// can swap awsSshModule.awsSshProvider per test case.
const { mockProvider, awsSshModule } = vi.hoisted(() => {
  const mockProvider = {
    ensureInstall: vi.fn(),
    submitPublicKey: vi.fn(),
    toCliRequest: vi.fn(),
    requestToSsh: vi.fn(),
    resolveHostKeys: vi.fn(),
  };
  return { mockProvider, awsSshModule: { awsSshProvider: mockProvider } };
});

vi.mock("../../../plugins/aws/ssh", () => awsSshModule);

const mockAuthn = {
  identity: { credential: { expires_at: 0 }, org: {} },
  getToken: vi.fn().mockResolvedValue("mock-token"),
} as unknown as Authn;

const requestId = "request-123";
const publicKey = "ssh-ed25519 AAAA...";

const baseArgs = {
  $0: "p0",
  _: ["ssh"],
  debug: true,
} satisfies yargs.ArgumentsCamelCase<BaseSshCommandArgs>;

const provisionedRequest = {
  permission: { provider: "aws" },
} as unknown as PermissionRequest<PluginSshRequest>;

describe("setupSshConnection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    awsSshModule.awsSshProvider = mockProvider;
  });

  it("calls each required ssh prep method", async () => {
    await setupSshConnection(
      mockAuthn,
      baseArgs,
      requestId,
      publicKey,
      provisionedRequest
    );

    expect(mockProvider.ensureInstall).toHaveBeenCalled();
    expect(mockProvider.submitPublicKey).toHaveBeenCalled();
    expect(mockProvider.toCliRequest).toHaveBeenCalled();
    expect(mockProvider.requestToSsh).toHaveBeenCalled();
    expect(mockProvider.resolveHostKeys).toHaveBeenCalled();
  });

  it("functions for providers without submitPublicKey/resolveHostKeys", async () => {
    // Partial provider omitting the two optional methods to exercise the ?. branch.
    awsSshModule.awsSshProvider = {
      ensureInstall: mockProvider.ensureInstall,
      toCliRequest: mockProvider.toCliRequest,
      requestToSsh: mockProvider.requestToSsh,
    } as typeof mockProvider;

    const result = await setupSshConnection(
      mockAuthn,
      baseArgs,
      requestId,
      publicKey,
      provisionedRequest
    );

    expect(mockProvider.submitPublicKey).not.toHaveBeenCalled();
    expect(mockProvider.resolveHostKeys).not.toHaveBeenCalled();
    expect(result.sshHostKeys).toBeUndefined();
  });

  it("returns host keys resolved by the provider", async () => {
    const hostKeys = {
      keys: ["ssh-ed25519 AAAAHOSTKEY..."],
    };
    mockProvider.resolveHostKeys.mockResolvedValue(hostKeys);

    const result = await setupSshConnection(
      mockAuthn,
      baseArgs,
      requestId,
      publicKey,
      provisionedRequest
    );

    expect(result.sshHostKeys).toBe(hostKeys);
  });
});
