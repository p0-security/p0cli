/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { arnPrefix, stsEndpoint } from "../api";
import { describe, expect, it } from "vitest";

describe("arnPrefix()", () => {
  it("defaults to the commercial partition when none is given", () => {
    expect(arnPrefix("123456789012")).toBe("arn:aws:iam::123456789012");
  });

  it("uses the commercial partition explicitly", () => {
    expect(arnPrefix("123456789012", "aws")).toBe("arn:aws:iam::123456789012");
  });

  it("emits a GovCloud ARN prefix", () => {
    expect(arnPrefix("145302212528", "aws-us-gov")).toBe(
      "arn:aws-us-gov:iam::145302212528"
    );
  });
});

describe("stsEndpoint()", () => {
  it("returns the regional commercial endpoint for aws", () => {
    expect(stsEndpoint("aws")).toBe("https://sts.us-east-1.amazonaws.com");
  });

  it("returns a GovCloud STS endpoint for aws-us-gov", () => {
    expect(stsEndpoint("aws-us-gov")).toBe(
      "https://sts.us-gov-east-1.amazonaws.com"
    );
  });

  it("falls back to the commercial endpoint for unknown partitions", () => {
    expect(stsEndpoint("aws-iso")).toBe("https://sts.us-east-1.amazonaws.com");
  });
});
