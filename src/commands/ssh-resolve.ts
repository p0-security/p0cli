/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
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
import { sys } from "typescript";
import yargs from "yargs";

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
        }),

    fsShutdownGuard(sshResolveAction)
  );

/** Connect to an SSH backend
 *
 * Implicitly gains access to the SSH resource if required.
 *
 * Supported SSH mechanisms:
 * - AWS EC2 via SSM with Okta SAML
 */
const sshResolveAction = async (
  args: yargs.ArgumentsCamelCase<SshResolveCommandArgs>
) => {
  const p0Executable = bootstrapConfig.appPath;
  // Prefix is required because the backend uses it to determine that this is an AWS request
  const authn = await authenticate({ noRefresh: args.quiet ?? false }).catch(
    conditionalAbortBeforeThrow(args.quiet ?? false)
  );

  const { request, provisionedRequest } = await prepareRequest(
    authn,
    args,
    args.destination,
    true,
    args.quiet
  ).catch(conditionalAbortBeforeThrow(args.quiet ?? false));

  const sshProvider = SSH_PROVIDERS[provisionedRequest.permission.provider];

  const keys = await sshProvider?.generateKeys?.(
    provisionedRequest.permission.resource,
    {
      debug: args.debug,
    }
  );

  const tmpFile = tmp.fileSync();
  fs.writeFileSync(tmpFile.name, JSON.stringify(request, null, 2));

  let linuxUserName = provisionedRequest.generated?.linuxUserName;

  if (provisionedRequest.permission.provider === "gcloud") {
    linuxUserName = (
      await sshProvider.toCliRequest(provisionedRequest, {
        debug: args.debug,
      })
    ).cliLocalData?.linuxUserName;
  }

  const identityFile =
    keys?.privateKeyPath ?? path.join(P0_PATH, "ssh", "id_rsa");
  const certificateInfo = keys?.certificatePath
    ? `CertificateFile ${keys.certificatePath}`
    : "";

  print2("=".repeat(80));
  print2(p0Executable);
  print2("=".repeat(80));
  const data = `
Hostname ${args.destination}
  User ${request.linuxUserName}
  IdentityFile ${identityFile}
  ${certificateInfo}
  PasswordAuthentication no
  ProxyCommand ${p0Executable} ssh-proxy %h --port %p --provider ${provisionedRequest.permission.provider} --identity-file ${identityFile} --request-json ${tmpFile.name}`;
  print2(data);
  print2("=".repeat(80));

  await fs.promises.mkdir(path.join(P0_PATH, "ssh", "configs"), {
    recursive: true,
  });
  const configLocation = path.join(
    P0_PATH,
    "ssh",
    "configs",
    `${args.destination}.config`
  );

  fs.writeFileSync(configLocation, data);
};
