/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

/**
 * Parses out Amazon Resource Names (ARNs) from AWS into their components. Note
 * that not all components are present in all ARNs (depending on the service;
 * for example, S3 ARNs don't have a region or account ID), and the final
 * component of the ARN (`resource`) may contain its own internal structure that
 * is also service-dependent and which may also include colons. In particular,
 * quoting the Amazon docs: "Be aware that the ARNs for some resources omit the
 * Region, the account ID, or both the Region and the account ID."
 *
 * @param arn The ARN to parse as a string.
 * @return A structure representing the components of the ARN. All fields will
 * be defined, but some may be empty strings if they are not present in the ARN.
 */
export const parseArn = (
  arn: string
): {
  partition: string;
  service: string;
  region: string;
  accountId: string;
  resource: string;
} => {
  // Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html
  const INVALID_ARN_MSG = `Invalid AWS ARN: ${arn}`;

  const parts = arn.split(":");

  if (parts.length < 6) {
    throw INVALID_ARN_MSG;
  }

  const [arnPrefix, partition, service, region, accountId, ...remainder] =
    parts;
  const resource = remainder.join(":");

  if (arnPrefix !== "arn") {
    throw `Invalid AWS ARN prefix "${arnPrefix}" in ARN: ${arn}`;
  }

  // We know these are all defined thanks to the parts.length check above, but
  // TypeScript doesn't, so....
  if (
    partition === undefined ||
    service === undefined ||
    accountId === undefined ||
    region === undefined
  ) {
    throw INVALID_ARN_MSG;
  }

  return {
    partition,
    service,
    region,
    accountId,
    resource,
  };
};
