/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { PRIVATE_KEY_PATH } from "../../common/keys";
import { asyncSpawn } from "../../common/subprocess";
import { print2 } from "../../drivers/stdio";
import { AgentArgs } from "./types";

const isSshAgentRunning = async (args: AgentArgs) => {
  try {
    if (args.debug) print2("Searching for active ssh-agents");
    // TODO: There's a possible edge-case but unlikely that ssh-agent has an invalid process or PID.
    // We can check to see if the active PID matches the current socket to mitigate this.
    await asyncSpawn(args, `pgrep`, ["-x", "ssh-agent"]);
    if (args.debug) print2("At least one SSH agent is running");
    return true;
  } catch {
    if (args.debug) print2("No SSH agent is running!");
    return false;
  }
};

const isSshAgentAuthSocketSet = async (args: AgentArgs) => {
  try {
    await asyncSpawn(args, `sh`, ["-c", '[ -n "$SSH_AUTH_SOCK" ]']);
    if (args.debug) print2(`SSH_AUTH_SOCK=${process.env.SSH_AUTH_SOCK}`);
    return true;
  } catch {
    if (args.debug) print2("SSH_AUTH_SOCK is not set!");
    return false;
  }
};

export const privateKeyExists = async (args: AgentArgs) => {
  try {
    await asyncSpawn(args, `sh`, [
      "-c",
      `KEY_PATH="${PRIVATE_KEY_PATH}" && KEY_FINGERPRINT=$(ssh-keygen -lf "$KEY_PATH" | awk '{print $2}') && ssh-add -l | grep -q "$KEY_FINGERPRINT" && exit 0 || exit 1`,
    ]);
    if (args.debug) print2("Private key exists in ssh agent");
    return true;
  } catch {
    if (args.debug) print2("Private key does not exist in ssh agent");
    return false;
  }
};

export const addPrivateKey = async (args: AgentArgs) => {
  try {
    await asyncSpawn(args, `ssh-add`, [
      PRIVATE_KEY_PATH,
      ...(args.debug ? ["-v", "-v", "-v"] : ["-q"]),
    ]);
    if (args.debug) print2("Private key added to ssh agent");
    return true;
  } catch {
    if (args.debug) print2("Failed to add private key to ssh agent");
    return false;
  }
};

export const withSshAgent = async <T>(
  args: AgentArgs,
  fn: () => Promise<T>
) => {
  const isRunning = await isSshAgentRunning(args);
  const hasSocket = await isSshAgentAuthSocketSet(args);
  if (!isRunning || !hasSocket) {
    throw "SSH agent is not running. Please start it by running: eval $(ssh-agent)";
  }

  const hasKey = await privateKeyExists(args);
  if (!hasKey) {
    await addPrivateKey(args);
  }

  return await fn();
};
