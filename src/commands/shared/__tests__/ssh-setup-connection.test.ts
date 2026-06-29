/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { Authn } from "../../../types/identity";
import { PermissionRequest } from "../../../types/request";
import { PluginSshRequest, SshProvider } from "../../../types/ssh";
import { BaseSshCommandArgs, SSH_PROVIDERS, setupSshConnection } from "../ssh";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import yargs from "yargs";

const mockEnsureInstall = vi.fn();
const mockSubmitPublicKey = vi.fn();
const mockToCliRequest = vi.fn();
const mockRequestToSsh = vi.fn();
const mockResolveHostKeys = vi.fn();

const mockProvider = {
  ensureInstall: mockEnsureInstall,
  submitPublicKey: mockSubmitPublicKey,
  toCliRequest: mockToCliRequest,
  requestToSsh: mockRequestToSsh,
  resolveHostKeys: mockResolveHostKeys,
} as unknown as SshProvider<any, any, any, any>;

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
  // setupSshConnection resolves the provider from the shared SSH_PROVIDERS record at call time, so overwrite the "aws" entry with the mock and restore it afterwards so it doesn't affect other tests.
  let originalProvider: SshProvider<any, any, any, any>;

  beforeEach(() => {
    vi.clearAllMocks();
    originalProvider = SSH_PROVIDERS.aws;
    SSH_PROVIDERS.aws = mockProvider;
  });

  afterEach(() => {
    SSH_PROVIDERS.aws = originalProvider;
  });

  it("calls each required ssh prep method", async () => {
    await setupSshConnection(
      mockAuthn,
      baseArgs,
      requestId,
      publicKey,
      provisionedRequest
    );

    expect(mockEnsureInstall).toHaveBeenCalled();
    expect(mockSubmitPublicKey).toHaveBeenCalled();
    expect(mockToCliRequest).toHaveBeenCalled();
    expect(mockRequestToSsh).toHaveBeenCalled();
    expect(mockResolveHostKeys).toHaveBeenCalled();
  });

  it("functions for providers without submitPublicKey/resolveHostKeys", async () => {
    // Same partial-mock cast as mockProvider, omitting the two optional methods to exercise the ?. branch.
    SSH_PROVIDERS.aws = {
      ensureInstall: mockEnsureInstall,
      toCliRequest: mockToCliRequest,
      requestToSsh: mockRequestToSsh,
    } as unknown as SshProvider<any, any, any, any>;

    const result = await setupSshConnection(
      mockAuthn,
      baseArgs,
      requestId,
      publicKey,
      provisionedRequest
    );

    expect(mockSubmitPublicKey).not.toHaveBeenCalled();
    expect(mockResolveHostKeys).not.toHaveBeenCalled();
    expect(result.sshHostKeys).toBeUndefined();
  });

  it("returns host keys resolved by the provider", async () => {
    const hostKeys = {
      keys: ["ssh-ed25519 AAAAHOSTKEY..."],
    };
    mockResolveHostKeys.mockResolvedValue(hostKeys);

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
