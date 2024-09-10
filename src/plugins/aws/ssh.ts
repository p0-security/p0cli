/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { SshProvider } from "../../types/ssh";
import { throwAssertNever } from "../../util";
import { assumeRoleWithOktaSaml } from "../okta/aws";
import { getAwsConfig } from "./config";
import { assumeRoleWithIdc } from "./idc";
import { ensureSsmInstall } from "./ssm/install";
import {
  AwsCredentials,
  AwsSshIdcRequest,
  AwsSshPermissionSpec,
  AwsSshRequest,
  AwsSshRoleRequest,
} from "./types";

/** Maximum number of attempts to start an SSH session
 *
 * Each attempt consumes ~ 1 s.
 */
const MAX_SSH_RETRIES = 30;

/** The name of the SessionManager port forwarding document. This document is managed by AWS.  */
const START_SSH_SESSION_DOCUMENT_NAME = "AWS-StartSSHSession";

export const awsSshProvider: SshProvider<
  AwsSshPermissionSpec,
  undefined,
  AwsSshRequest,
  AwsCredentials
> = {
  requestToSsh: (request) => {
    const { permission, generated } = request;
    const { instanceId, accountId, region } = permission.spec;
    const { idc, ssh, name } = generated;
    const { linuxUserName } = ssh;
    const common = { linuxUserName, accountId, region, id: instanceId };
    return !idc
      ? { ...common, role: name, type: "aws", access: "role" }
      : {
          ...common,
          idc,
          permissionSet: name,
          type: "aws",
          access: "idc",
        };
  },
  toCliRequest: async (request) => ({ ...request, cliLocalData: undefined }),
  ensureInstall: async () => {
    if (!(await ensureSsmInstall())) {
      throw "Please try again after installing the required AWS utilities";
    }
  },
  cloudProviderLogin: async (authn, request) => {
    const { config } = await getAwsConfig(authn, request.accountId);
    if (!config.login?.type || config.login?.type === "iam") {
      throw "This account is not configured for SSH access via the P0 CLI";
    }

    return config.login?.type === "idc"
      ? await assumeRoleWithIdc(request as AwsSshIdcRequest)
      : config.login?.type === "federated"
        ? await assumeRoleWithOktaSaml(authn, request as AwsSshRoleRequest)
        : throwAssertNever(config.login);
  },
  proxyCommand: (request) => {
    return [
      "aws",
      "ssm",
      "start-session",
      "--region",
      request.region,
      "--target",
      "%h",
      "--document-name",
      START_SSH_SESSION_DOCUMENT_NAME,
      "--parameters",
      '"portNumber=%p"',
    ];
  },
  reproCommands: (request) => {
    // TODO: Add manual commands for IDC login
    if (request.access !== "idc") {
      return [
        `eval $(p0 aws role assume ${request.role} --account ${request.accountId})`,
      ];
    }
    return undefined;
  },
  preTestAccessPropagationArgs: () => undefined,
  maxRetries: MAX_SSH_RETRIES,
  friendlyName: "AWS",
};
