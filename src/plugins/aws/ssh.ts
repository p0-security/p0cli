/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { PRIVATE_KEY_PATH, saveHostKeys } from "../../common/keys";
import { submitPublicKey } from "../../drivers/api";
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

const PROPAGATION_TIMEOUT_LIMIT_MS = 30 * 1000;

/** The name of the SessionManager port forwarding document. This document is managed by AWS.  */
const START_SSH_SESSION_DOCUMENT_NAME = "AWS-StartSSHSession";

/**There are 2 cases of unprovisioned access in AWS
 * 1. SSM:StartSession action is missing either on the SSM document (AWS-StartSSHSession) or the EC2 instance
 * 2. Temporary error when issuing an SCP command
 *
 * 1: results in UNAUTHORIZED_START_SESSION_MESSAGE
 * 2: results in CONNECTION_CLOSED_MESSAGE
 */
const unprovisionedAccessPatterns = [
  /** Matches the error message that AWS SSM prints when access is not propagated */
  // Note that the resource will randomly be either the SSM document or the EC2 instance
  {
    pattern:
      /An error occurred \(AccessDeniedException\) when calling the StartSession operation: User: arn:.*:sts::.*:assumed-role\/P0GrantsRole.* is not authorized to perform: ssm:StartSession on resource: arn:.*:.*:.*:.* because no identity-based policy allows the ssm:StartSession action/,
  },
  /**
   * Matches the following error messages that AWS SSM pints when ssh authorized
   * key access hasn't propagated to the instance yet.
   * - Connection closed by UNKNOWN port 65535
   * - scp: Connection closed
   * - kex_exchange_identification: Connection closed by remote host
   */
  {
    pattern: /\bConnection closed\b.*\b(?:by UNKNOWN port \d+|by remote host)?/,
  },
] as const;

export const awsSshProvider: SshProvider<
  AwsSshPermissionSpec,
  undefined,
  AwsSshRequest,
  AwsCredentials
> = {
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

  ensureInstall: async () => {
    if (!(await ensureSsmInstall())) {
      throw "Please try again after installing the required AWS utilities";
    }
  },

  friendlyName: "AWS",

  propagationTimeoutMs: PROPAGATION_TIMEOUT_LIMIT_MS,

  preTestAccessPropagationArgs: () => undefined,

  async submitPublicKey(authn, request, requestId, publicKey) {
    if (request.generated.publicKey) {
      if (request.generated.publicKey !== publicKey) {
        throw "Public key mismatch. Please revoke the request and try again.";
      }
    } else {
      await submitPublicKey(authn, { publicKey, requestId });
    }
  },

  proxyCommand: (request, port) => {
    return [
      "aws",
      "ssm",
      "start-session",
      "--region",
      request.region,
      "--target",
      request.id,
      "--document-name",
      START_SSH_SESSION_DOCUMENT_NAME,
      "--parameters",
      port ? `portNumber=${port}` : "portNumber=%p",
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

  generateKeys: async () => {
    return {
      privateKeyPath: PRIVATE_KEY_PATH,
    };
  },

  saveHostKeys: async (request, options) => {
    const { hostKeys, id } = request;
    const path = await saveHostKeys(id, hostKeys, { ...options });
    return path ? { alias: id, path } : undefined;
  },

  requestToSsh: (request) => {
    const { permission, generated } = request;
    const { resource, region } = permission;
    const { idcId, idcRegion, instanceId, accountId } = resource;
    const { linuxUserName, hostKeys, resource: generatedResource } = generated;
    const { name } = generatedResource;
    const common = {
      linuxUserName,
      accountId,
      region,
      id: instanceId,
      hostKeys,
    };
    return !idcId || !idcRegion
      ? { ...common, role: name, type: "aws", access: "role" }
      : {
          ...common,
          idc: { id: idcId, region: idcRegion },
          permissionSet: name,
          type: "aws",
          access: "idc",
        };
  },

  toCliRequest: async (request) => ({ ...request, cliLocalData: undefined }),

  unprovisionedAccessPatterns,
};
