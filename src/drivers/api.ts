/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { ExerciseGrantResponse } from "../commands/shared";
import { config } from "../drivers/env";
import { Authn } from "../types/identity";
import * as path from "node:path";
import yargs from "yargs";

const tenantUrl = (tenant: string) => `${config.appUrl}/o/${tenant}`;

const commandUrl = (tenant: string) => `${tenantUrl(tenant)}/command/`;

const exerciseGrantUrl = (tenant: string) =>
  `${tenantUrl(tenant)}/exercise-grant/`;

export const fetchCommand = async <T>(
  authn: Authn,
  args: yargs.ArgumentsCamelCase,
  argv: string[]
) =>
  baseFetch<T>(
    authn,
    commandUrl(authn.identity.org.slug),
    "POST",
    JSON.stringify({
      argv,
      scriptName: path.basename(args.$0),
    })
  );

export const fetchExerciseGrant = async (
  authn: Authn,
  args: {
    type: "scp" | "ssh";
    requestId: string;
    destination: string;
    publicKey?: string;
  }
) =>
  baseFetch<ExerciseGrantResponse>(
    authn,
    exerciseGrantUrl(authn.identity.org.slug),
    "POST",
    JSON.stringify(args)
  );

export const baseFetch = async <T>(
  authn: Authn,
  url: string,
  method: string,
  body: string
) => {
  const token = await authn.userCredential.user.getIdToken();
  const response = await fetch(url, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body,
  });
  const text = await response.text();
  const data = JSON.parse(text);
  if ("error" in data) {
    throw data.error;
  }
  return data as T;
};
