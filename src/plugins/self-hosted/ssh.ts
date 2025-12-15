/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { isSudoCommand } from "../../commands/shared/ssh";
import { createKeyPair } from "../../common/keys";
import { print2 } from "../../drivers/stdio";
import { SshProvider } from "../../types/ssh";
import { getAppName, getOperatingSystem } from "../../util";
import { createTempDirectoryForKeys } from "../ssh/shared";
import { breakGlassCredentials } from "./break-glass";
import { generateSelfHostedCertificate } from "./keygen";
import { SelfHostedSshPermissionSpec, SelfHostedSshRequest } from "./types";
import * as fs from "fs/promises";
import path from "node:path";

// We pass in the name of the certificate file to generate
export const SELF_HOSTED_CERT_FILENAME = "p0cli-self-hosted-ssh-cert.pub";

const PROPAGATION_TIMEOUT_LIMIT_MS = 2 * 60 * 1000;

const unprovisionedAccessPatterns = [
  { pattern: /Permission denied \(publickey\)/ },
  {
    // The output of `sudo -v` when the user is not allowed to run sudo
    pattern: /Sorry, user .+ may not run sudo on .+/,
  },
  {
    pattern: /Connection closed by UNKNOWN port 65535/,
  },
] as const;

export const selfHostedSshProvider: SshProvider<
  SelfHostedSshPermissionSpec,
  undefined,
  SelfHostedSshRequest
> = {
  cloudProviderLogin: async () => undefined,
  ensureInstall: async () => {},

  friendlyName: "Self-hosted",

  get loginRequiredMessage() {
    return `Please login with '${getAppName()} login'`;
  },

  propagationTimeoutMs: PROPAGATION_TIMEOUT_LIMIT_MS,

  preTestAccessPropagationArgs: (cmdArgs) => {
    if (isSudoCommand(cmdArgs)) {
      return {
        ...cmdArgs,
        // `sudo -v` prints `Sorry, user <user> may not run sudo on <hostname>.` to stderr when user is not a sudoer.
        // It prints nothing to stdout when user is a sudoer - which is important because we don't want any output from the pre-test.
        command: "sudo",
        arguments: ["-v"],
      };
    }
    return undefined;
  },

  generateKeys: async (authn, request, options) => {
    // Check if break-glass user is specified
    if (request.breakGlassUser) {
      const { sshCertificateKeyPath, sshPrivateKeyPath, sshKeyPathCleanup } =
        await breakGlassCredentials(authn, options);
      if (options.debug) {
        print2(
          `Using break-glass credentials with certificatePath: ${sshCertificateKeyPath} and identityFile: ${sshPrivateKeyPath}`
        );
      }
      return {
        certificatePath: sshCertificateKeyPath,
        privateKeyPath: sshPrivateKeyPath,
        teardown: sshKeyPathCleanup,
      };
    }
    // Normal flow: generate keys locally
    const { path: keyPath } = await createTempDirectoryForKeys();
    const { publicKey } = await createKeyPair();

    const signedCertificate = await generateSelfHostedCertificate(authn, {
      ...options,
      publicKey,
    });

    const certificatePath = path.join(keyPath, SELF_HOSTED_CERT_FILENAME);
    await fs.writeFile(certificatePath, signedCertificate);
    if (options.debug) {
      print2(
        `Using locally generated credentials with certificatePath: ${certificatePath}`
      );
    }
    return {
      certificatePath,
    };
  },

  setup: async (authn, request, options) => {
    // Check if break-glass user is specified
    if (request.breakGlassUser) {
      const { sshCertificateKeyPath, sshPrivateKeyPath, sshKeyPathCleanup } =
        await breakGlassCredentials(authn, options);
      if (options.debug) {
        print2(
          `Using break-glass credentials with sshCertificateKeyPath: ${sshCertificateKeyPath} and sshPrivateKeyPath: ${sshPrivateKeyPath}`
        );
      }
      return {
        sshOptions: [`CertificateFile=${sshCertificateKeyPath}`],
        identityFile: sshPrivateKeyPath,
        teardown: sshKeyPathCleanup,
      };
    }
    // Normal flow: generate keys locally
    const { path: keyPath, cleanup: sshKeyPathCleanup } =
      await createTempDirectoryForKeys();

    const { publicKey } = await createKeyPair();

    const signedCertificate = await generateSelfHostedCertificate(authn, {
      debug: options.debug,
      requestId: options.requestId,
      publicKey,
    });
    const sshCertificateKeyPath = path.join(keyPath, SELF_HOSTED_CERT_FILENAME);
    await fs.writeFile(sshCertificateKeyPath, signedCertificate);

    return {
      sshOptions: [`CertificateFile=${sshCertificateKeyPath}`],
      teardown: sshKeyPathCleanup,
    };
  },

  proxyCommand: (request, port) => {
    const targetPort = port ?? "22";
    // On Windows, use ncat (from nmap). On Unix/Mac, use nc.
    // Both have the same command line syntax: command localhost port
    const command = getOperatingSystem() === "win" ? "ncat" : "nc";
    return [command, request.id, targetPort];
  },

  reproCommands: () => undefined,

  requestToSsh: (request) => {
    return {
      id: request.permission.resource.publicIp,
      linuxUserName: request.generated.linuxUserName,
      type: "self-hosted",
      breakGlassUser: request.permission.breakGlassUser,
    };
  },

  unprovisionedAccessPatterns,

  toCliRequest: async (request) => ({ ...request, cliLocalData: undefined }),
};
