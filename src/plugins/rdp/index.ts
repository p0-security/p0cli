/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { decodeProvisionStatus } from "../../commands/shared";
import { request } from "../../commands/shared/request";
import { createKeyPair } from "../../common/keys";
import {
  fetchIntegrationConfig,
  submitProxyPublicKey,
} from "../../drivers/api";
import { getContactMessage } from "../../drivers/config";
import { print2 } from "../../drivers/stdio";
import { exitProcess } from "../../opentelemetry/otel-helpers";
import { Authn } from "../../types/identity";
import {
  AzureRdpRequest,
  ProxyRdpRequest,
  RdpCommandArgs,
  RdpRequest,
} from "../../types/rdp";
import { PermissionRequest } from "../../types/request";
import { getOperatingSystem } from "../../util";
import { azureRdpProvider } from "../azure/rdp";
import { proxyRdpProvider } from "../proxy/rdp";
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
    return await request("request")<PermissionRequest<RdpRequest>>(
      {
        ...pick(args, "$0", "_"),
        arguments: [
          "rdp",
          "session",
          destination,
          ...(args.provider ? ["--provider", args.provider] : []),
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

  const result = await decodeProvisionStatus<RdpRequest>(response.request);

  if (!result) exitProcess(1);

  return {
    requestId: response.id,
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

  const { requestId, provisionedRequest } = result;
  return { requestId, request: provisionedRequest };
};

export const rdp = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<RdpCommandArgs>
) => {
  const { requestId, request } = await prepareRequest(authn, args);
  const provider = args.provider ?? request.permission.provider ?? "entra";

  const { configure, debug } = args;

  if (provider === "proxy") {
    const { publicKey } = await createKeyPair();
    if (debug) {
      print2(`Submitting public key:\n${publicKey}`);
    }
    await submitProxyPublicKey(authn, { publicKey, requestId }, debug);

    const proxyRequest = request as PermissionRequest<ProxyRdpRequest>;
    await proxyRdpProvider.setup(proxyRequest, { debug });
    await proxyRdpProvider.spawnConnection(authn, proxyRequest, {
      configure,
      debug,
    });
  } else {
    // Entra ID authentication is only supported on Windows client machines.
    // See: https://learn.microsoft.com/en-us/windows/client-management/client-tools/connect-to-remote-aadj-pc#connect-with-microsoft-entra-authentication
    const os = getOperatingSystem();
    if (os !== "win") {
      print2("RDP session connections are only supported on Windows.");
      exitProcess(1);
    }

    const azureRequest = request as PermissionRequest<AzureRdpRequest>;
    await azureRdpProvider.setup(azureRequest, { debug });
    await azureRdpProvider.spawnConnection(azureRequest, { configure, debug });
  }
};
