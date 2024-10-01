/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { CommandArgs } from "../commands/shared/ssh";
import {
  AwsSsh,
  AwsSshPermissionSpec,
  AwsSshRequest,
} from "../plugins/aws/types";
import {
  GcpSsh,
  GcpSshPermissionSpec,
  GcpSshRequest,
} from "../plugins/google/types";
import { Authn } from "./identity";
import { Request } from "./request";

export type CliSshRequest = AwsSsh | GcpSsh;
export type PluginSshRequest = AwsSshPermissionSpec | GcpSshPermissionSpec;

export type CliPermissionSpec<
  P extends PluginSshRequest,
  C extends object | undefined,
> = P & {
  cliLocalData: C;
};

// The prefix of installed SSH accounts in P0 is the provider name
export const SupportedSshProviders = ["aws", "gcloud"] as const;
export type SupportedSshProvider = (typeof SupportedSshProviders)[number];

export type SshProvider<
  PR extends PluginSshRequest = PluginSshRequest,
  O extends object | undefined = undefined,
  SR extends SshRequest = SshRequest,
  C extends object | undefined = undefined, // credentials object
> = {
  requestToSsh: (request: CliPermissionSpec<PR, O>) => SR;
  /** Converts a backend request to a CLI request */
  toCliRequest: (
    request: Request<PR>,
    options?: { debug?: boolean }
  ) => Promise<Request<CliSshRequest>>;
  ensureInstall: () => Promise<void>;
  /** Logs in the user to the cloud provider */
  cloudProviderLogin: (authn: Authn, request: SR) => Promise<C>;
  /** Returns the command and its arguments that are going to be injected as the ssh ProxyCommand option */
  proxyCommand: (request: SR) => string[];
  /** Each element in the returned array is a command that can be run to reproduce the
   * steps of logging in the user to the ssh session. */
  reproCommands: (request: SR) => string[] | undefined;
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
  timeLimit: number;
  friendlyName: string;
};

export type SshRequest = AwsSshRequest | GcpSshRequest;
