/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { config } from "../drivers/env";
import { Authn } from "../types/identity";
import * as path from "node:path";
import yargs from "yargs";

const commandUrl = (tenant: string) => `${config.appUrl}/o/${tenant}/command/`;

export const fetchCommand = async <T>(
  authn: Authn,
  args: yargs.ArgumentsCamelCase,
  argv: string[]
) => {
  const token = await authn.userCredential.user.getIdToken();
  const response = await fetch(commandUrl(authn.identity.org.slug), {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      argv,
      scriptName: path.basename(args.$0),
    }),
  });
  const text = await response.text();
  const data = JSON.parse(text);
  if ("error" in data) {
    throw data.error;
  }
  return data as T;
};
