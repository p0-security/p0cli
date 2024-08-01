/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { waitForProvisioning } from ".";
import { createKeyPair } from "../../common/keys";
import { doc } from "../../drivers/firestore";
import { print2 } from "../../drivers/stdio";
import { awsSshProvider } from "../../plugins/aws/ssh";
import { AwsSshRequest } from "../../plugins/aws/types";
import { gcpSshProvider } from "../../plugins/google/ssh";
import { GcpSshRequest } from "../../plugins/google/types";
import { SshConfig } from "../../plugins/ssh/types";
import { Authn } from "../../types/identity";
import { CliRequest, PluginRequest, Request } from "../../types/request";
import { request } from "../request";
import { getDoc } from "firebase/firestore";
import { pick } from "lodash";
import yargs from "yargs";

// The prefix of installed SSH accounts in P0 is the provider name
export const SUPPORTED_PROVIDERS = ["aws", "gcloud"];

export type SshRequest = AwsSshRequest | GcpSshRequest;

export type BaseSshCommandArgs = {
  sudo?: boolean;
  reason?: string;
  account?: string;
  provider?: (typeof SUPPORTED_PROVIDERS)[number];
  debug?: boolean;
};

export type ScpCommandArgs = BaseSshCommandArgs & {
  source: string;
  destination: string;
  recursive?: boolean;
};

export type SshCommandArgs = BaseSshCommandArgs & {
  sudo?: boolean;
  destination: string;
  L?: string; // Port forwarding option
  N?: boolean; // No remote command
  A?: boolean;
  arguments: string[];
  command?: string;
};

const SSH_PROVIDERS = {
  aws: awsSshProvider,
  gcloud: gcpSshProvider,
};

const validateSshInstall = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<BaseSshCommandArgs>
) => {
  const configDoc = await getDoc<SshConfig, object>(
    doc(`o/${authn.identity.org.tenantId}/integrations/ssh`)
  );
  const configItems = configDoc.data()?.["iam-write"];

  const providersToCheck = args.provider
    ? [args.provider]
    : SUPPORTED_PROVIDERS;

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
  request: Request<PluginRequest>,
  options?: { debug?: boolean }
): Promise<Request<CliRequest>> =>
  await SSH_PROVIDERS[request.permission.spec.type].toCliRequest(
    request as any,
    options
  );

export const provisionRequest = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<BaseSshCommandArgs>,
  destination: string
) => {
  await validateSshInstall(authn, args);

  const { publicKey, privateKey } = await createKeyPair();

  const response = await request<PluginRequest>(
    {
      ...pick(args, "$0", "_"),
      arguments: [
        "ssh",
        "session",
        destination,
        "--public-key",
        publicKey,
        ...(args.provider ? ["--provider", args.provider] : []),
        ...(args.sudo || args.command === "sudo" ? ["--sudo"] : []),
        ...(args.reason ? ["--reason", args.reason] : []),
        ...(args.account ? ["--account", args.account] : []),
      ],
      wait: true,
    },
    authn,
    { message: "approval-required" }
  );

  if (!response) {
    print2("Did not receive access ID from server");
    return;
  }
  const { id, isPreexisting } = response;
  if (!isPreexisting) print2("Waiting for access to be provisioned");

  const provisionedRequest = await waitForProvisioning<PluginRequest>(
    authn,
    id
  );
  if (provisionedRequest.permission.spec.publicKey !== publicKey) {
    throw "Public key mismatch. Please revoke the request and try again.";
  }

  const cliRequest = await pluginToCliRequest(provisionedRequest, {
    debug: args.debug,
  });

  return { request: cliRequest, publicKey, privateKey };
};

export const requestToSsh = (request: Request<CliRequest>): SshRequest =>
  SSH_PROVIDERS[request.permission.spec.type].requestToSsh(request as any);
