/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { parseArn } from "../utils";

describe("parseArn() function", () => {
  it.each([
    "badarn:aws:ec2:us-east-1:123456789012:vpc/vpc-0e9801d129EXAMPLE", // Bad prefix
    ":aws:ec2:us-east-1:123456789012:vpc/vpc-0e9801d129EXAMPLE", // Missing prefix
    "arn:aws:ec2:us-east-1:123456789012", // Too few elements
  ])('Raises an "Invalid ARN" error', (arn) => {
    expect(() => parseArn(arn)).toThrow("Invalid AWS ARN");
  });

  it("Parses a valid ARN with all fields correctly", () => {
    const arn = "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0e9801d129EXAMPLE";

    const parsed = parseArn(arn);

    expect(parsed).toEqual({
      partition: "aws",
      service: "ec2",
      region: "us-east-1",
      accountId: "123456789012",
      resource: "vpc/vpc-0e9801d129EXAMPLE",
    });
  });

  it("Parses a valid ARN with colons in the resource correctly", () => {
    // Note: This is not the format we would expect an EKS ARN to actually be in (it should
    // use a / instead of a : in the resource); this is just for unit testing purposes.
    const arn = "arn:aws:eks:us-west-2:123456789012:cluster:my-testing-cluster";

    const parsed = parseArn(arn);

    expect(parsed).toEqual({
      partition: "aws",
      service: "eks",
      region: "us-west-2",
      accountId: "123456789012",
      resource: "cluster:my-testing-cluster",
    });
  });

  it("Parses a valid ARN with no region correctly", () => {
    const arn = "arn:aws:iam::123456789012:user/johndoe";

    const parsed = parseArn(arn);

    expect(parsed).toEqual({
      partition: "aws",
      service: "iam",
      region: "",
      accountId: "123456789012",
      resource: "user/johndoe",
    });
  });

  it("Parses a valid ARN with no account ID correctly", () => {
    // Note: This is not a valid SNS ARN; they would ordinarily have an account ID. This is
    // just for unit testing purposes.
    const arn = "arn:aws-us-gov:sns:us-east-1::example-sns-topic-name";

    const parsed = parseArn(arn);

    expect(parsed).toEqual({
      partition: "aws-us-gov",
      service: "sns",
      region: "us-east-1",
      accountId: "",
      resource: "example-sns-topic-name",
    });
  });

  it("Parses a valid ARN with no region or account ID correctly", () => {
    const arn = "arn:aws-cn:s3:::my-corporate-bucket";

    const parsed = parseArn(arn);

    expect(parsed).toEqual({
      partition: "aws-cn",
      service: "s3",
      region: "",
      accountId: "",
      resource: "my-corporate-bucket",
    });
  });
});
