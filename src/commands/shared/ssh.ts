/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { decodeProvisionStatus } from ".";
import { createKeyPair } from "../../common/keys";
import { fetchIntegrationConfig } from "../../drivers/api";
import { getContactMessage } from "../../drivers/config";
import { print2 } from "../../drivers/stdio";
import { awsSshProvider } from "../../plugins/aws/ssh";
import { azureSshProvider } from "../../plugins/azure/ssh";
import { gcpSshProvider } from "../../plugins/google/ssh";
import { selfHostedSshProvider } from "../../plugins/self-hosted/ssh";
import { SshConfig } from "../../plugins/ssh/types";
import { Authn } from "../../types/identity";
import { PermissionRequest } from "../../types/request";
import {
  CliSshRequest,
  PluginSshRequest,
  SshProvider,
  SupportedSshProvider,
  SupportedSshProviders,
} from "../../types/ssh";
import { request } from "./request";
import { pick } from "lodash";
import { sys } from "typescript";
import yargs from "yargs";

export type BaseSshCommandArgs = {
  sudo?: boolean;
  reason?: string;
  parent?: string;
  provider?: SupportedSshProvider;
  debug?: boolean;
  sshOptions?: string[];
};

export type ScpCommandArgs = BaseSshCommandArgs & {
  source: string;
  destination: string;
};

export type SshCommandArgs = BaseSshCommandArgs & {
  sudo?: boolean;
  destination: string;
  arguments: string[];
  command?: string;
};

export type SshResolveCommandArgs = SshCommandArgs & {
  quiet?: boolean;
};

export type SshProxyCommandArgs = {
  destination: string;
  port: string;
  provider: "aws" | "azure" | "gcloud";
  requestJson: string;
  debug?: boolean;
  identityFile: string;
};

export type CommandArgs = ScpCommandArgs | SshCommandArgs;

export type SshRequestOptions = {
  approvedOnly?: boolean;
  quiet?: boolean;
};

export type SshAdditionalSetup = {
  /** A list of SSH configuration options, as would be used after '-o' in an SSH command */
  sshOptions: string[];

  /** The path to the private key file to use for the SSH connection, instead of the default P0 CLI managed key */
  identityFile?: string;

  /** The port to connect to, overriding the default */
  port?: string;

  /** Perform any teardown required after the SSH command exits but before terminating the P0 CLI */
  teardown: () => Promise<void>;
};

export const SSH_PROVIDERS: Record<
  SupportedSshProvider,
  SshProvider<any, any, any, any>
> = {
  aws: awsSshProvider,
  azure: azureSshProvider,
  gcloud: gcpSshProvider,
  "self-hosted": selfHostedSshProvider,
};

const validateSshInstall = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<BaseSshCommandArgs>
) => {
  const configDoc = await fetchIntegrationConfig<{ config: SshConfig }>(
    authn,
    "ssh",
    args.debug
  );
  const configItems = configDoc?.config["iam-write"];

  const providersToCheck = args.provider
    ? [args.provider]
    : SupportedSshProviders;

  const items = Object.entries(configItems ?? {}).filter(
    ([key, value]) =>
      value.state == "installed" &&
      providersToCheck.some((prefix) => key.startsWith(prefix))
  );

  if (items.length === 0) {
    throw "This organization is not configured for SSH access";
  }
};

export const isSudoCommand = (args: { sudo?: boolean; command?: string }) =>
  args.sudo || args.command === "sudo";

export const provisionRequest = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<BaseSshCommandArgs>,
  destination: string,
  options?: SshRequestOptions
) => {
  await validateSshInstall(authn, args);

  const { publicKey, privateKey } = await createKeyPair();

  const makeRequest = async (requestOptions?: { forceSudo: boolean }) => {
    return await request("request")<PermissionRequest<PluginSshRequest>>(
      {
        ...pick(args, "$0", "_"),
        arguments: [
          "ssh",
          "session",
          destination,
          "--public-key",
          publicKey,
          ...(options?.approvedOnly ? ["--approved"] : []),
          ...(args.provider ? ["--provider", args.provider] : []),
          ...(requestOptions?.forceSudo || isSudoCommand(args)
            ? ["--sudo"]
            : []),
          ...(args.reason ? ["--reason", args.reason] : []),
          ...(args.parent ? ["--parent", args.parent] : []),
        ],
        wait: true,
        debug: args.debug,
      },
      authn,
      { message: options?.quiet ? "quiet" : "approval-required" }
    );
  };

  const requestErrorHandler = (err: any) => {
    if (typeof err === "string") {
      print2(err);
      if (
        err.startsWith("Could not find any instances matching") &&
        err.includes("@")
      ) {
        print2(
          "Hint: The instance-name appears to contain a username AND a hostname; only the hostname is required."
        );
      }
    }
    sys.exit(1);
  };

  let response;
  if (options?.approvedOnly) {
    // Try first with sudo
    try {
      response = await makeRequest({ forceSudo: true }).catch(
        requestErrorHandler
      );
    } catch (error) {
      // If that fails, try without sudo
      if (args.debug) {
        print2("Request with sudo failed, retrying without sudo");
      }
      response = await makeRequest().catch(requestErrorHandler);
    }
  } else {
    // Normal behavior when not approvedOnly
    response = await makeRequest().catch(requestErrorHandler);
  }

  if (!response) {
    if (!options?.quiet) {
      print2("Did not receive access ID from server");
    }
    return;
  }

  const { id, isPreexisting } = response;

  const message = isPreexisting
    ? "Existing access found.  Connecting to instance."
    : "Waiting for access to be provisioned";
  print2(message);

  const result = await decodeProvisionStatus<PluginSshRequest>(
    response.request
  );

  if (!result) sys.exit(1);

  return {
    requestId: id,
    provisionedRequest: response.request,
    publicKey,
    privateKey,
  };
};

const pluginToCliRequest = async (
  request: PermissionRequest<PluginSshRequest>,
  options: { debug?: boolean; publicKey: string }
): Promise<PermissionRequest<CliSshRequest>> =>
  await SSH_PROVIDERS[request.permission.provider].toCliRequest(
    request as any,
    options
  );

export const prepareRequest = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<BaseSshCommandArgs>,
  destination: string,
  options?: SshRequestOptions
) => {
  const result = await provisionRequest(authn, args, destination, options);
  if (!result) {
    throw `Server did not return a request id. ${getContactMessage()}`;
  }

  const { requestId, publicKey, provisionedRequest } = result;

  const sshProvider = SSH_PROVIDERS[provisionedRequest.permission.provider];

  await sshProvider.submitPublicKey?.(
    authn,
    provisionedRequest,
    requestId,
    publicKey,
    args.debug
  );

  await sshProvider.ensureInstall();

  const cliRequest = await pluginToCliRequest(provisionedRequest, {
    ...args,
    publicKey,
  });

  const request = sshProvider.requestToSsh(cliRequest);

  const sshHostKeys = await sshProvider.saveHostKeys?.(request, args);

  return { ...result, request, sshProvider, provisionedRequest, sshHostKeys };
};
