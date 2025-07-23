/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { waitForProvisioning } from ".";
import { createKeyPair } from "../../common/keys";
import { fetchIntegrationConfig } from "../../drivers/api";
import { getContactMessage } from "../../drivers/config";
import { print2 } from "../../drivers/stdio";
import { awsSshProvider } from "../../plugins/aws/ssh";
import { azureSshProvider } from "../../plugins/azure/ssh";
import { gcpSshProvider } from "../../plugins/google/ssh";
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
  recursive?: boolean;
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

export type SshAdditionalSetup = {
  /** A list of SSH configuration options, as would be used after '-o' in an SSH command */
  sshOptions: string[];

  /** The path to the private key file to use for the SSH connection, instead of the default P0 CLI managed key */
  identityFile: string;

  /** The port to connect to, overriding the default */
  port: string;

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
};

const validateSshInstall = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<BaseSshCommandArgs>
) => {
  const configDoc = await fetchIntegrationConfig<{ config: SshConfig }>(
    authn,
    "ssh"
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
    throw "This organization is not configured for SSH access via the P0 CLI";
  }
};

const pluginToCliRequest = async (
  request: PermissionRequest<PluginSshRequest>,
  options?: { debug?: boolean }
): Promise<PermissionRequest<CliSshRequest>> =>
  await SSH_PROVIDERS[request.permission.provider].toCliRequest(
    request as any,
    options
  );

export const isSudoCommand = (args: { sudo?: boolean; command?: string }) =>
  args.sudo || args.command === "sudo";

export const provisionRequest = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<BaseSshCommandArgs>,
  destination: string,
  approvedOnly?: boolean,
  quiet?: boolean
) => {
  await validateSshInstall(authn, args);

  const { publicKey, privateKey } = await createKeyPair();

  const response = await request("request")<PluginSshRequest>(
    {
      ...pick(args, "$0", "_"),
      arguments: [
        "ssh",
        "session",
        destination,
        "--public-key",
        publicKey,
        ...(approvedOnly ? ["--approved"] : []),
        ...(args.provider ? ["--provider", args.provider] : []),
        ...(isSudoCommand(args) ? ["--sudo"] : []),
        ...(args.reason ? ["--reason", args.reason] : []),
        ...(args.parent ? ["--parent", args.parent] : []),
      ],
      wait: true,
    },
    authn,
    { message: quiet ? "quiet" : "approval-required" }
  );

  if (!response) {
    if (!quiet) {
      print2("Did not receive access ID from server");
    }
    return;
  }
  const { id, isPreexisting } = response;
  if (!isPreexisting) print2("Waiting for access to be provisioned");
  else print2("Existing access found.  Connecting to instance.");

  const provisionedRequest = await waitForProvisioning<PluginSshRequest>(
    authn,
    id
  );

  return { requestId: id, provisionedRequest, publicKey, privateKey };
};

export const prepareRequest = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<BaseSshCommandArgs>,
  destination: string,
  approvedOnly?: boolean,
  quiet?: boolean
) => {
  const result = await provisionRequest(
    authn,
    args,
    destination,
    approvedOnly,
    quiet
  );
  if (!result) {
    throw `Server did not return a request id. ${getContactMessage()}`;
  }

  const { requestId, publicKey, provisionedRequest } = result;

  const sshProvider = SSH_PROVIDERS[provisionedRequest.permission.provider];

  await sshProvider.submitPublicKey?.(
    authn,
    provisionedRequest,
    requestId,
    publicKey
  );

  await sshProvider.ensureInstall();

  const cliRequest = await pluginToCliRequest(provisionedRequest, {
    debug: args.debug,
  });
  const request = sshProvider.requestToSsh(cliRequest);

  return { ...result, request, sshProvider, provisionedRequest };
};
