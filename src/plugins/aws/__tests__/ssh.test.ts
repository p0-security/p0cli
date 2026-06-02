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
  delegation: {},
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
        buildRequest({ aws: AWS_DELEGATE_IDC })
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
        buildRequest({ aws: AWS_DELEGATE_ROLE })
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
        buildRequest({ aws: AWS_DELEGATE_IDC })
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

  it("emits POSIX command substitution for a role request under bash", () => {
    process.env.SHELL = "/bin/bash";
    expect(awsSshProvider.reproCommands(ROLE_REQUEST)).toEqual([
      "$(p0 aws role assume Role1 --account 123456789012 --no-request)",
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
