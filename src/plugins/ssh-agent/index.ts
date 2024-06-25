/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { AgentArgs, SshAgentEnv } from "./types";
import { SpawnOptionsWithoutStdio, spawn } from "node:child_process";

const AUTH_SOCK_MESSAGE = /SSH_AUTH_SOCK=(.+?);/;
const AGENT_PID_MESSAGE = /SSH_AGENT_PID=(\d+?);/;

/** Spawns a subprocess with given command, args, and options.
 * May write content to its standard input.
 * Stdout and stderr of the subprocess is printed to stderr in debug mode.
 * The returned promise resolves or rejects with the exit code. */
const asyncSpawn = async (
  { debug }: AgentArgs,
  command: string,
  args?: ReadonlyArray<string>,
  options?: SpawnOptionsWithoutStdio,
  writeStdin?: string
) =>
  new Promise<number>((resolve, reject) => {
    const child = spawn(command, args, options);

    if (writeStdin) {
      if (!child.stdin) return reject("Child process has no stdin");
      child.stdin.write(writeStdin);
    }

    child.stdout.on("data", (data) => {
      if (debug) {
        print2(data.toString("utf-8"));
      }
    });

    child.stderr.on("data", (data) => {
      if (debug) {
        print2(data.toString("utf-8"));
      }
    });

    child.on("exit", (code) => {
      if (code !== 0) {
        return reject(code);
      }
      resolve(code);
    });

    if (writeStdin) {
      child.stdin?.end();
    }
  });

/** Spawns a subprocess with the ssh-agent command.
 * Detects the auth socket and agent PID from stdout.
 * Stdout and stderr of the subprocess is printed to stderr in debug mode.
 * The returned promise resolves with an object that contains the auth socket and agent PID,
 * or rejects with the contents of stderr. */
export const sshAgent = async (cmdArgs: AgentArgs) =>
  new Promise<SshAgentEnv>((resolve, reject) => {
    let stderr = "";
    let stdout = "";

    // There is a debug flag in ssh-agent but it causes the ssh-agent process to NOT fork
    const child = spawn("ssh-agent");

    child.stdout.on("data", (data) => {
      const str = data.toString("utf-8");
      if (cmdArgs.debug) {
        print2(str);
      }
      stdout += str;
    });

    child.stderr.on("data", (data) => {
      const str = data.toString("utf-8");
      if (cmdArgs.debug) {
        print2(str);
      }
      stderr += str;
    });

    const exitListener = child.on("exit", (code) => {
      exitListener.unref();

      if (code !== 0) {
        return reject(stderr);
      }

      const authSockMatch = stdout.match(AUTH_SOCK_MESSAGE);
      const agentPidMatch = stdout.match(AGENT_PID_MESSAGE);

      if (!authSockMatch?.[1] || !agentPidMatch?.[1]) {
        return reject("Failed to parse ssh-agent stdout:\n" + stdout);
      }
      resolve({
        SSH_AUTH_SOCK: authSockMatch[1],
        SSH_AGENT_PID: agentPidMatch[1],
      });
    });
  });

const sshAgentKill = async (args: AgentArgs, sshAgentEnv: SshAgentEnv) =>
  asyncSpawn(args, "ssh-agent", ["-k"], {
    env: { ...process.env, ...sshAgentEnv },
  });

export const sshAdd = async (
  args: AgentArgs,
  sshAgentEnv: SshAgentEnv,
  privateKey: string
) =>
  asyncSpawn(
    args,
    "ssh-add",
    // In debug mode do not use the quiet flag. There is no debug flag in ssh-add.
    // Instead increase to maximum verbosity of 3 with -v flag.
    args.debug ? ["-v", "-v", "-v", "-"] : ["-q", "-"],
    { env: { ...process.env, ...sshAgentEnv } },
    privateKey
  );

export const sshAddList = async (args: AgentArgs, sshAgentEnv: SshAgentEnv) =>
  asyncSpawn(args, "ssh-add", ["-l"], {
    env: { ...process.env, ...sshAgentEnv },
  });

export const withSshAgent = async <T>(
  args: AgentArgs,
  fn: (sshAgentEnv: SshAgentEnv) => Promise<T>
) => {
  const sshAgentEnv = await sshAgent(args);
  try {
    return await fn(sshAgentEnv);
  } finally {
    // keep the ssh-agent alive in debug mode
    if (!args.debug) await sshAgentKill(args, sshAgentEnv);
  }
};
