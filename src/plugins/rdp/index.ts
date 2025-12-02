/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { decodeProvisionStatus } from "../../commands/shared";
import { request } from "../../commands/shared/request";
import { fetchIntegrationConfig } from "../../drivers/api";
import { getContactMessage } from "../../drivers/config";
import { print2 } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import { AzureRdpRequest, RdpCommandArgs } from "../../types/rdp";
import { PermissionRequest } from "../../types/request";
import { azureRdpProvider } from "../azure/rdp";
import { pick } from "lodash";
import yargs from "yargs";

const validateRdpInstall = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<RdpCommandArgs>
) => {
  const configDoc = await fetchIntegrationConfig<{
    config: {
      "iam-write": Record<string, { state: string }>;
    };
  }>(authn, "rdp", args.debug);
  const configItems = configDoc?.config["iam-write"];

  const items = Object.entries(configItems ?? {}).filter(
    ([_key, value]) => value.state === "installed"
  );

  if (items.length === 0) {
    throw "This organization is not configured for RDP access";
  }
};

const provisionRequest = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<RdpCommandArgs>
) => {
  await validateRdpInstall(authn, args);

  const { destination } = args;

  const makeRequest = async () => {
    return await request("request")<PermissionRequest<AzureRdpRequest>>(
      {
        ...pick(args, "$0", "_"),
        arguments: [
          "rdp",
          "session",
          destination,
          ...(args.reason ? ["--reason", args.reason] : []),
        ],
        wait: true,
        debug: args.debug,
        configure: args.configure,
      },
      authn
    );
  };

  const response = await makeRequest();

  if (!response) {
    print2("Did not receive access ID from server");
    return;
  }

  const { isPreexisting } = response;

  const message = isPreexisting
    ? "Existing access found.  Connecting to instance."
    : "Waiting for access to be provisioned";
  print2(message);

  decodeProvisionStatus<AzureRdpRequest>(response.request);

  return {
    provisionedRequest: response.request,
  };
};

const prepareRequest = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<RdpCommandArgs>
) => {
  const result = await provisionRequest(authn, args);
  if (!result) {
    throw `Server did not return a request id. ${getContactMessage()}`;
  }

  const { provisionedRequest } = result;
  return { request: provisionedRequest };
};

export const rdp = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<RdpCommandArgs>
) => {
  const { request } = await prepareRequest(authn, args);

  const { configure, debug } = args;
  await azureRdpProvider.setup(request, { debug });

  await azureRdpProvider.spawnConnection(request, {
    configure,
    debug,
  });
};
