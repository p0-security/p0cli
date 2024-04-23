/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchExerciseGrant } from "../drivers/api";
import { authenticate } from "../drivers/auth";
import { guard } from "../drivers/firestore";
import { scp } from "../plugins/aws/ssm";
import {
  ExerciseGrantResponse,
  ScpCommandArgs,
  provisionRequest,
} from "./shared";
import * as fs from "fs/promises";
import * as sshpk from "sshpk";
import yargs from "yargs";

export const scpCommand = (yargs: yargs.Argv) =>
  yargs.command<ScpCommandArgs>(
    "scp <source> <destination>",
    // TODO: support scp across multiple remote hosts.
    "SCP copies files between a local and remote host.",
    (yargs) =>
      yargs
        .positional("source", {
          type: "string",
          demandOption: true,
          description: "Format: [hostname:]file or file",
        })
        .positional("destination", {
          type: "string",
          demandOption: true,
          description: "Format: [hostname:]file or file",
        })
        .option("i", {
          alias: "identity",
          type: "string",
          describe:
            "Selects a file from which the identity (private key) for public key authentication is read",
          demandOption: true,
        })
        .option("r", {
          alias: "recursive",
          type: "boolean",
          describe: "Recursively copy entire directories",
        })
        .option("reason", {
          describe: "Reason access is needed",
          type: "string",
        })
        .option("account", {
          type: "string",
          describe: "The account on which the instance is located",
        })
        .option("sudo", {
          type: "boolean",
          describe: "Add user to sudoers file",
        }),
    guard(scpAction)
  );

/** Transfers files between a local and remote hosts using SSH.
 *
 * Implicitly gains access to the SSH resource if required.
 */
const scpAction = async (args: yargs.ArgumentsCamelCase<ScpCommandArgs>) => {
  const authn = await authenticate();

  const host = getHostIdentifier(args.source, args.destination);

  if (!host) {
    throw "Could not determine host identifier from source or destination";
  }

  const requestId = await provisionRequest(authn, args, host);

  if (!requestId) {
    throw "Server did not return a request id. Please contact support@p0.dev for assistance.";
  }

  if (!args.identity) {
    throw "Please provide a path to the identity file";
  }

  const identity = await fs.readFile(args.identity, "utf8");
  if (!identity) {
    throw "Could not read identity file, please check the path and try again.";
  }

  const result = await fetchExerciseGrant(authn, {
    requestId,
    destination: host,
    // Generates the public key from the private key which prevents having to pass the public key separately.
    // Works with rsa/ed25519 algorithms and keys generated with ssh-keygen or openssl.
    publicKey: sshpk.parseKey(identity, "pem").toString("ssh"),
  });

  // replace the host with the linuxUserName@instanceId
  const { source, destination } = replaceHostWithInstance(result, args);

  await scp(authn, result, {
    ...args,
    source,
    destination,
  });
};

/** If a path is not explicitly local, use this pattern to determine if it's remote */
const REMOTE_PATTERN_COLON = /^([^:]+:)(.*)$/; // Matches host:[path]

const isExplicitlyRemote = (path: string): boolean => {
  return REMOTE_PATTERN_COLON.test(path);
};

const getHostIdentifier = (source: string, destination: string) => {
  // the instance is contained in the source or destination and is always delimited by a colon.
  const isSourceRemote = isExplicitlyRemote(source);
  const isDestinationRemote = isExplicitlyRemote(destination);

  const remote = isSourceRemote ? source : destination;

  if (isSourceRemote != isDestinationRemote) {
    return remote.split(":")[0];
  }

  throw "At least one host (source or destination) must be remote.";
};

const replaceHostWithInstance = (
  result: ExerciseGrantResponse,
  args: ScpCommandArgs
) => {
  let source = args.source;
  let destination = args.destination;

  if (isExplicitlyRemote(source)) {
    source = `${result.linuxUserName}@${result.instance.id}:${source.split(":")[1]}`;
  }

  if (isExplicitlyRemote(destination)) {
    destination = `${result.linuxUserName}@${result.instance.id}:${destination.split(":")[1]}`;
  }

  return { source, destination };
};
