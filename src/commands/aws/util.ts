/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import { PluginRequest } from "../../types/request";
import { waitForProvisioning } from "../shared";
import { request } from "../shared/request";
import yargs from "yargs";

export const PROVISIONING_ACCESS_MESSAGE =
  "Waiting for access to be provisioned";
export const EXISTING_ACCESS_MESSAGE = "Existing access found.";
export const ACCESS_EXISTS_ERROR_MESSAGE =
  "This principal already has this access";

export const provisionRequest = async (
  argv: yargs.ArgumentsCamelCase<{
    arguments: string[];
    wait?: boolean;
  }>,
  authn: Authn
) => {
  try {
    const response = await request("request")(argv, authn, {
      message: "approval-required",
    });

    if (!response) {
      print2("Did not receive access ID from server");
      return;
    }

    const { id, isPreexisting } = response;

    print2(
      !isPreexisting ? PROVISIONING_ACCESS_MESSAGE : EXISTING_ACCESS_MESSAGE
    );
    await waitForProvisioning<PluginRequest>(authn, id);
  } catch (error) {
    if (error === ACCESS_EXISTS_ERROR_MESSAGE) {
      print2(EXISTING_ACCESS_MESSAGE);
    } else {
      throw error;
    }
  }
};
