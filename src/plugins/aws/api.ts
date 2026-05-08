/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
export const AWS_API_VERSION = "2011-06-15";

export const arnPrefix = (account: string, partition: string = "aws") =>
  `arn:${partition}:iam::${account}`;

/** Returns a regional STS endpoint for the given AWS partition.
 *
 * Regional endpoints issue v2 tokens valid in all regions of the partition.
 * Falls back to commercial us-east-1 for unknown partitions. */
export const stsEndpoint = (partition: string): string => {
  switch (partition) {
    case "aws-us-gov":
      return "https://sts.us-gov-east-1.amazonaws.com";
    case "aws":
    default:
      return "https://sts.us-east-1.amazonaws.com";
  }
};
