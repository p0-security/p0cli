/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { CommandArgs, SshAdditionalSetup } from "../commands/shared/ssh";
import {
  AwsSsh,
  AwsSshPermissionSpec,
  AwsSshRequest,
} from "../plugins/aws/types";
import {
  AzureSsh,
  AzureSshPermissionSpec,
  AzureSshRequest,
} from "../plugins/azure/types";
import {
  GcpSsh,
  GcpSshPermissionSpec,
  GcpSshRequest,
} from "../plugins/google/types";
import { Authn } from "./identity";
import { Request } from "./request";

export type CliSshRequest = AwsSsh | AzureSsh | GcpSsh;
export type PluginSshRequest =
  | AwsSshPermissionSpec
  | AzureSshPermissionSpec
  | GcpSshPermissionSpec;

export type CliPermissionSpec<
  P extends PluginSshRequest,
  C extends object | undefined,
> = P & {
  cliLocalData: C;
};

// The prefix of installed SSH accounts in P0 is the provider name
export const SupportedSshProviders = ["aws", "azure", "gcloud"] as const;
export type SupportedSshProvider = (typeof SupportedSshProviders)[number];

export type AccessPattern = {
  /** If the error matches this string, indicates that access is not provisioned */
  readonly pattern: RegExp;
  /** Maximum amount of time to wait for provisioning after encountering this error */
  readonly validationWindowMs?: number;
};

export type SshProvider<
  PR extends PluginSshRequest = PluginSshRequest,
  O extends object | undefined = undefined,
  SR extends SshRequest = SshRequest,
  C extends object | undefined = undefined, // credentials object
> = {
  /** Logs in the user to the cloud provider */
  cloudProviderLogin: (authn: Authn, request: SR) => Promise<C>;

  /** Callback to ensure that this provider's CLI utils are installed */
  ensureInstall: () => Promise<void>;

  /** Validate the SSH key if necessary; throw an exception if the key is invalid */
  validateSshKey?: (request: Request<PR>, publicKey: string) => boolean;

  /** A human-readable name for this CSP */
  friendlyName: string;

  /** Friendly message to ask the user to log in to the CSP */
  loginRequiredMessage?: string;

  /** Regex match for error string indicating that CSP login is required */
  loginRequiredPattern?: RegExp;

  /** Amount of time, in ms, to wait between granting access and giving up on attempting an SSH connection */
  propagationTimeoutMs: number;

  /** Arguments for a pre-test command to verify access propagation prior
   * to actually logging in the user to the ssh session.
   * This must return arguments for a non-interactive command - meaning the `command`
   * and potentially the `args` props must be specified in the returned scp/ssh command.
   * If the return value is undefined then no pre-testing is done prior to executing
   * the actual ssh/scp command.
   */
  preTestAccessPropagationArgs: (
    cmdArgs: CommandArgs
  ) => CommandArgs | undefined;

  /** Perform any setup required before running the SSH command. Returns a list of additional arguments to pass to the
   * SSH command. */
  setup?: (
    request: SR,
    options?: { debug?: boolean }
  ) => Promise<SshAdditionalSetup>;

  /** Returns the command and its arguments that are going to be injected as the ssh ProxyCommand option */
  proxyCommand: (request: SR, port?: string) => string[];

  /** Each element in the returned array is a command that can be run to reproduce the
   * steps of logging in the user to the ssh session. */
  reproCommands: (
    request: SR,
    additionalData?: SshAdditionalSetup
  ) => string[] | undefined;

  /** Unwraps this provider's types */
  requestToSsh: (request: CliPermissionSpec<PR, O>) => SR;

  /** Regex matches for error strings indicating that the provider has not yet fully provisioned node access */
  unprovisionedAccessPatterns: readonly AccessPattern[];

  /** Regex matches for error strings indicating that the provider is ready for node access.
   * Used to override error codes during access propagation testing.
   */
  provisionedAccessPatterns?: readonly AccessPattern[];

  /** Regex matches for error strings indicating that the provider has fully provisioned */

  /** Converts a backend request to a CLI request */
  toCliRequest: (
    request: Request<PR>,
    options?: { debug?: boolean }
  ) => Promise<Request<CliSshRequest>>;
};

export type SshRequest = AwsSshRequest | AzureSshRequest | GcpSshRequest;
