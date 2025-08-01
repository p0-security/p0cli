/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchIntegrationConfig } from "../../drivers/api";
import { Authn } from "../../types/identity";
import { AwsConfig } from "./types";
import { sortBy } from "lodash";

export const getFirstAwsConfig = async (authn: Authn) => {
  const { identity } = authn;
  const { config } = await fetchIntegrationConfig<{ config: AwsConfig }>(
    authn,
    "aws"
  );

  const item = Object.entries(config?.["iam-write"] ?? {}).find(
    ([_id, { state }]) => state === "installed"
  );

  if (!item) throw `P0 is not installed on any AWS account`;

  return { identity, config: { id: item[0], ...item[1] } };
};

export const getAwsConfig = async (
  authn: Authn,
  account: string | undefined
) => {
  const { identity } = authn;
  const { config } = await fetchIntegrationConfig<{ config: AwsConfig }>(
    authn,
    "aws"
  );
  // TODO: Support alias lookup
  const allItems = sortBy(
    Object.entries(config?.["iam-write"] ?? {}).filter(
      ([, { state }]) => state === "installed"
    ),
    ([id]) => id
  );
  const item = account
    ? allItems.find(([id, { label }]) => id === account || label === account)
    : allItems.length !== 1
      ? (() => {
          throw `Please select a unique AWS account with --account; valid accounts are:\n${allItems.map(([id, { label }]) => label ?? id).join("\n")}`;
        })()
      : allItems[0];
  if (!item) throw `P0 is not installed on AWS account ${account}`;
  return { identity, config: { id: item[0], ...item[1] } };
};
