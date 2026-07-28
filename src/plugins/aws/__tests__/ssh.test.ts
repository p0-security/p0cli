/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { CliPermissionSpec } from "../../../types/ssh";
import { awsSshProvider } from "../ssh";
import {
  AwsResourcePermissionSpec,
  AwsSshGenerated,
  AwsSshPermission,
  AwsSshPermissionSpec,
  AwsSshRequest,
} from "../types";
import { afterEach, describe, expect, it, vi } from "vitest";

// Keep the printed app name deterministic; spread the original so the real
// detectShell/newShellFormatter (which read process.env.SHELL) are used.
vi.mock("../../../util", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../../util")>()),
  getAppName: () => "p0",
}));

type SshRequest = CliPermissionSpec<AwsSshPermissionSpec, undefined>;

const AWS_DELEGATE_IDC: AwsResourcePermissionSpec = {
  type: "aws",
  permission: {
    account: "acct",
    accountId: "111111111111",
    arn: "arn:aws:iam::111111111111:role/foo",
    idcId: "idc-1",
    idcRegion: "us-east-1",
    name: "permset",
  },
  generated: { name: "delegated-name" },
  delegation: [],
};

const AWS_DELEGATE_ROLE: AwsResourcePermissionSpec = {
  ...AWS_DELEGATE_IDC,
  permission: {
    ...AWS_DELEGATE_IDC.permission,
    idcId: undefined,
    idcRegion: undefined,
  },
};

const PERMISSION_BASE: AwsSshPermission = {
  provider: "aws",
  publicKey: "pub-key",
  region: "us-east-1",
  alias: "alias",
  resource: {
    instanceId: "i-abc123",
    userName: "ec2-user",
  },
};

const GENERATED: AwsSshGenerated = {
  hostKeys: ["host-key"],
  linuxUserName: "linux-user",
  publicKey: "pub-key",
  resource: { name: "fallback-name" },
};

const buildRequest = (
  delegation: AwsSshPermissionSpec["delegation"],
  permission: AwsSshPermission = PERMISSION_BASE
): SshRequest => ({
  type: "ssh",
  permission,
  generated: GENERATED,
  delegation,
  cliLocalData: undefined,
});

describe("awsSshProvider.requestToSsh", () => {
  describe("legacy record-form delegation", () => {
    it("builds an IDC request when idc fields are populated", () => {
      const result = awsSshProvider.requestToSsh(
        buildRequest([{ key: "aws", request: AWS_DELEGATE_IDC }])
      );
      expect(result).toEqual({
        type: "aws",
        access: "idc",
        accountId: "111111111111",
        id: "i-abc123",
        region: "us-east-1",
        linuxUserName: "linux-user",
        hostKeys: ["host-key"],
        idc: { id: "idc-1", region: "us-east-1" },
        permissionSet: "delegated-name",
      });
    });

    it("builds a role request when idc fields are absent", () => {
      const result = awsSshProvider.requestToSsh(
        buildRequest([{ key: "aws", request: AWS_DELEGATE_ROLE }])
      );
      expect(result).toEqual({
        type: "aws",
        access: "role",
        accountId: "111111111111",
        id: "i-abc123",
        region: "us-east-1",
        linuxUserName: "linux-user",
        hostKeys: ["host-key"],
        role: "delegated-name",
      });
    });
  });

  describe("new array-form delegation", () => {
    it("builds an IDC request when idc fields are populated", () => {
      const result = awsSshProvider.requestToSsh(
        buildRequest([{ key: "aws", request: AWS_DELEGATE_IDC }])
      );
      expect(result).toEqual({
        type: "aws",
        access: "idc",
        accountId: "111111111111",
        id: "i-abc123",
        region: "us-east-1",
        linuxUserName: "linux-user",
        hostKeys: ["host-key"],
        idc: { id: "idc-1", region: "us-east-1" },
        permissionSet: "delegated-name",
      });
    });

    it("builds a role request when idc fields are absent", () => {
      const result = awsSshProvider.requestToSsh(
        buildRequest([{ key: "aws", request: AWS_DELEGATE_ROLE }])
      );
      expect(result).toEqual({
        type: "aws",
        access: "role",
        accountId: "111111111111",
        id: "i-abc123",
        region: "us-east-1",
        linuxUserName: "linux-user",
        hostKeys: ["host-key"],
        role: "delegated-name",
      });
    });

    it("produces the same output as the record form for equivalent input", () => {
      const recordResult = awsSshProvider.requestToSsh(
        buildRequest([{ key: "aws", request: AWS_DELEGATE_IDC }])
      );
      const arrayResult = awsSshProvider.requestToSsh(
        buildRequest([{ key: "aws", request: AWS_DELEGATE_IDC }])
      );
      expect(arrayResult).toEqual(recordResult);
    });
  });

  describe("fallback to resource", () => {
    it("falls back to resource when delegation has no aws entry (array form)", () => {
      const permissionWithFullResource: AwsSshPermission = {
        ...PERMISSION_BASE,
        resource: {
          ...PERMISSION_BASE.resource,
          account: "fallback-acct",
          accountId: "999999999999",
          arn: "arn:aws:iam::999999999999:role/fallback",
          idcId: undefined,
          idcRegion: undefined,
          name: "fallback-role",
        },
      };
      const result = awsSshProvider.requestToSsh(
        buildRequest([], permissionWithFullResource)
      );
      expect(result).toMatchObject({
        type: "aws",
        access: "role",
        accountId: "999999999999",
        role: "fallback-name",
      });
    });

    it("throws when neither delegation nor resource provides accountId", () => {
      expect(() => awsSshProvider.requestToSsh(buildRequest([]))).toThrow(
        "Backend did not provide an AWS account ID for SSH session."
      );
    });
  });
});

describe("awsSshProvider.reproCommands", () => {
  const ROLE_REQUEST: AwsSshRequest = {
    type: "aws",
    access: "role",
    role: "Role1",
    accountId: "123456789012",
    region: "us-east-1",
    id: "i-abc123",
    linuxUserName: "ec2-user",
    hostKeys: [],
  };

  const IDC_REQUEST: AwsSshRequest = {
    type: "aws",
    access: "idc",
    permissionSet: "permset",
    idc: { id: "idc-1", region: "us-east-1" },
    accountId: "123456789012",
    region: "us-east-1",
    id: "i-abc123",
    linuxUserName: "ec2-user",
    hostKeys: [],
  };

  const originalShell = process.env.SHELL;
  afterEach(() => {
    process.env.SHELL = originalShell;
  });

  it("emits an eval-wrapped command substitution for a role request under bash", () => {
    process.env.SHELL = "/bin/bash";
    expect(awsSshProvider.reproCommands(ROLE_REQUEST)).toEqual([
      'eval "$(p0 aws role assume Role1 --account 123456789012 --no-request)"',
    ]);
  });

  it("emits fish-compatible piping for a role request when the login shell is fish", () => {
    process.env.SHELL = "/usr/bin/fish";
    expect(awsSshProvider.reproCommands(ROLE_REQUEST)).toEqual([
      "p0 aws role assume Role1 --account 123456789012 --no-request | source",
    ]);
  });

  it("returns undefined for IDC requests regardless of shell", () => {
    process.env.SHELL = "/usr/bin/fish";
    expect(awsSshProvider.reproCommands(IDC_REQUEST)).toBeUndefined();
  });
});

// A StartSession failure is "terminal" when retrying cannot fix it (bad
// signature/middlebox 403, expired or unknown credentials); the propagation
// retry loop aborts on these instead of waiting out the 30s window. The named
// IAM AccessDeniedException emitted while a fresh grant propagates must NOT be
// terminal — that one self-heals and stays retryable (CX-464).
describe("terminal StartSession failure classification", () => {
  // Verbatim from a customer --debug log (CX-464).
  const REJECTED_403_LINE =
    "aws: [ERROR]: An error occurred (403) when calling the StartSession operation: Server authentication failed: <UnauthorizedRequest><message>Forbidden.</message></UnauthorizedRequest>";

  const EXPIRED_TOKEN_LINE =
    "An error occurred (ExpiredTokenException) when calling the StartSession operation: The security token included in the request is expired";

  const PROPAGATION_DENIAL_LINE =
    "An error occurred (AccessDeniedException) when calling the StartSession operation: User: arn:aws:sts::630172805352:assumed-role/P0GrantsRole30/user is not authorized to perform: ssm:StartSession on resource: arn:aws:ec2:us-west-2:630172805352:instance/i-abc123 because no identity-based policy allows the ssm:StartSession action";

  const REQUEST = { region: "us-west-2" } as AwsSshRequest;

  const matchesTerminal = (line: string) =>
    awsSshProvider.terminalAccessPatterns!.some((message) =>
      line.match(message.pattern)
    );

  it("classifies the 403 <UnauthorizedRequest> rejection as terminal", () => {
    expect(matchesTerminal(REJECTED_403_LINE)).toBe(true);
  });

  it("classifies expired credentials as terminal", () => {
    expect(matchesTerminal(EXPIRED_TOKEN_LINE)).toBe(true);
  });

  it("keeps the propagation-phase IAM denial retryable, not terminal", () => {
    expect(matchesTerminal(PROPAGATION_DENIAL_LINE)).toBe(false);
    expect(
      awsSshProvider.unprovisionedAccessPatterns.some((message) =>
        PROPAGATION_DENIAL_LINE.match(message.pattern)
      )
    ).toBe(true);
  });

  it("connectionErrorMessage surfaces the raw error line with actionable hints", () => {
    const stderr = `debug1: Executing proxy command\n${REJECTED_403_LINE}\nkex_exchange_identification: Connection closed by remote host\n`;
    const message = awsSshProvider.connectionErrorMessage!(stderr, REQUEST);

    expect(message).toContain(REJECTED_403_LINE);
    expect(message).toContain("not an access-propagation delay");
    expect(message).toContain("config.fish");
    expect(message).toContain("ssm.us-west-2.amazonaws.com");
  });

  it("connectionErrorMessage falls through on unclassified stderr", () => {
    expect(
      awsSshProvider.connectionErrorMessage!(
        "kex_exchange_identification: Connection closed by remote host\n",
        REQUEST
      )
    ).toBeUndefined();
  });
});
