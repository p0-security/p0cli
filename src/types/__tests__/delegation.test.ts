/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { DelegationField, getDelegate } from "../delegation";
import { describe, expect, it } from "vitest";

type AwsDelegate = {
  permission: { accountId: string; arn: string };
  generated: { name: string };
};

type AwsRdsDelegate = {
  permission: { vpcId: string };
  delegation: DelegationField<{ aws: AwsDelegate }>;
};

const AWS_DELEGATE: AwsDelegate = {
  permission: { accountId: "123456789012", arn: "arn:aws:iam::123:role/Foo" },
  generated: { name: "Foo" },
};

describe("getDelegate", () => {
  describe("array form", () => {
    it("returns the matching entry's request, stamped with its key as `type`", () => {
      const delegation: DelegationField<{ aws: AwsDelegate }> = [
        { key: "aws", request: AWS_DELEGATE },
      ];
      expect(getDelegate(delegation, "aws")).toEqual({
        ...AWS_DELEGATE,
        type: "aws",
      });
    });

    it("returns undefined when no entry matches the key", () => {
      const delegation: DelegationField<{ aws?: AwsDelegate }> = [];
      expect(getDelegate(delegation, "aws")).toBeUndefined();
    });

    it("scans past non-matching entries to find the requested key", () => {
      type Multi = { aws?: AwsDelegate; gcp?: AwsDelegate };
      const other: AwsDelegate = {
        permission: { accountId: "other", arn: "arn:gcp" },
        generated: { name: "gcp" },
      };
      const delegation: DelegationField<Multi> = [
        { key: "gcp", request: other },
        { key: "aws", request: AWS_DELEGATE },
      ];
      expect(getDelegate(delegation, "aws")).toEqual({
        ...AWS_DELEGATE,
        type: "aws",
      });
    });

    it("returns the first matching entry when keys are duplicated", () => {
      const first: AwsDelegate = {
        permission: { accountId: "first", arn: "arn:first" },
        generated: { name: "first" },
      };
      const second: AwsDelegate = {
        permission: { accountId: "second", arn: "arn:second" },
        generated: { name: "second" },
      };
      const delegation: DelegationField<{ aws: AwsDelegate }> = [
        { key: "aws", request: first },
        { key: "aws", request: second },
      ];
      expect(getDelegate(delegation, "aws")).toEqual({ ...first, type: "aws" });
    });

    it("handles nested array-form delegation by chaining calls", () => {
      const delegation: DelegationField<{ "aws-rds": AwsRdsDelegate }> = [
        {
          key: "aws-rds",
          request: {
            permission: { vpcId: "vpc-1" },
            delegation: [{ key: "aws", request: AWS_DELEGATE }],
          },
        },
      ];
      const rds = getDelegate(delegation, "aws-rds");
      expect(getDelegate(rds?.delegation, "aws")).toEqual({
        ...AWS_DELEGATE,
        type: "aws",
      });
    });

    it("ignores malformed entries (missing key) without throwing", () => {
      const delegation = [
        null,
        undefined,
        { key: "aws", request: AWS_DELEGATE },
      ] as any;
      expect(getDelegate(delegation, "aws")).toEqual({
        ...AWS_DELEGATE,
        type: "aws",
      });
    });
  });

  describe("nullish input", () => {
    it("returns undefined when delegation is undefined", () => {
      expect(getDelegate(undefined, "aws")).toBeUndefined();
    });

    it("returns undefined when delegation is null", () => {
      expect(getDelegate(null, "aws")).toBeUndefined();
    });
  });
});
