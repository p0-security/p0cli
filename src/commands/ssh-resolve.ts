/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { sanitizeAsFileName } from "../common/destination";
import { PRIVATE_KEY_PATH } from "../common/keys";
import { authenticate } from "../drivers/auth";
import { bootstrapConfig } from "../drivers/env";
import { fsShutdownGuard } from "../drivers/firestore";
import { print2 } from "../drivers/stdio";
import { conditionalAbortBeforeThrow, P0_PATH } from "../util";
import {
  SSH_PROVIDERS,
  SshResolveCommandArgs,
  prepareRequest,
} from "./shared/ssh";
import fs from "fs";
import path from "path";
import tmp from "tmp-promise";
import yargs from "yargs";

const ENV_PREFIX = "P0_SSH";

export const sshResolveCommand = (yargs: yargs.Argv) =>
  yargs.command<SshResolveCommandArgs>(
    "ssh-resolve <destination>",
    "SSH into a virtual machine",
    (yargs) =>
      yargs
        .positional("destination", {
          type: "string",
          demandOption: true,
        })
        .option("parent", {
          type: "string",
          describe:
            "The containing parent resource which the instance belongs to (account, project, subscription, etc.)",
        })
        .option("provider", {
          type: "string",
          describe: "The cloud provider where the instance is hosted",
          choices: ["aws", "azure", "gcloud"],
        })
        .option("debug", {
          type: "boolean",
          describe: "Print debug information.",
        })
        .option("quiet", {
          alias: "q",
          type: "boolean",
          describe: "Suppress output",
        })
        .option("reason", {
          describe: "Reason access is needed",
          type: "string",
        })
        .env(ENV_PREFIX),

    fsShutdownGuard(sshResolveAction)
  );

/** Determine if an SSH backend is accessible to the user and prepares local files for access
 *
 * Creates an access request with approvedOnly and creates any
 * key or credential files necessary for the SSH connection.
 * Finally writes any ssh settings to an ssh config for use by
 * a parent ssh process
 *
 */
const sshResolveAction = async (
  args: yargs.ArgumentsCamelCase<SshResolveCommandArgs>
) => {
  const silentlyExit = conditionalAbortBeforeThrow(args.quiet ?? false);

  const requestErrorHandler = (err: any) => {
    if (
      typeof err === "string" &&
      err.toLowerCase().includes("reason is required")
    ) {
      print2(
        `Please set the ${ENV_PREFIX}_REASON environment variable or request access with "p0 request ssh ... --reason ..." to the destination first.`
      );
    }
    return silentlyExit(err);
  };

  const authn = await authenticate({ noRefresh: true }).catch(silentlyExit);

  const { request, provisionedRequest } = await prepareRequest(
    authn,
    args,
    args.destination,
    true,
    args.quiet
  ).catch(requestErrorHandler);

  const sshProvider = SSH_PROVIDERS[provisionedRequest.permission.provider];

  if (args.debug) {
    print2("Generating Keys");
  }
  const keys = await sshProvider?.generateKeys?.(
    provisionedRequest.permission.resource,
    {
      debug: args.debug,
    }
  );

  const tmpFile = tmp.fileSync();

  if (args.debug) {
    print2("Writing request output to disk for use by ssh-proxy");
  }
  fs.writeFileSync(tmpFile.name, JSON.stringify(request, null, 2));

  const identityFile = keys?.privateKeyPath ?? PRIVATE_KEY_PATH;
  const certificateInfo = keys?.certificatePath
    ? `CertificateFile ${keys.certificatePath}`
    : "";

  const p0Executable = bootstrapConfig.appPath;

  // The config file name must be a valid file name (without forward slashes) so we can create it.
  // The config file will be deleted by the ssh-proxy command. Sanitization here and upon deletion must match.
  const configFile = sanitizeAsFileName(args.destination);

  // `Host` matches the destination entered in the `ssh` command. The rest of the config
  // options will be used if there is a match.
  // `Hostname` is used to translate the `Host` to a host name. If the ProxyCommand used
  // a tool like `ssh` or `nc`, this would have to be a DNS-resolvable host name or an IP
  // address. Since we are using `p0 ssh-proxy`, it can be anything as long as we resolve it.
  const data = `Host ${args.destination}
  Hostname ${args.destination}
  User ${request.linuxUserName}
  IdentityFile ${identityFile}
  ${certificateInfo}
  PasswordAuthentication no
  ProxyCommand ${p0Executable} ssh-proxy %h --port %p --provider ${provisionedRequest.permission.provider} --identity-file ${identityFile} --request-json ${tmpFile.name} ${args.debug ? "--debug" : ""}`;

  await fs.promises.mkdir(path.join(P0_PATH, "ssh", "configs"), {
    recursive: true,
  });

  const configLocation = path.join(
    P0_PATH,
    "ssh",
    "configs",
    `${configFile}.config`
  );

  if (args.debug) {
    print2("Writing ssh config file");
    print2(data);
  }
  fs.writeFileSync(configLocation, data);
};
