/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { retryWithSleep } from "../../common/retry";
import { print2 } from "../../drivers/stdio";
import { osSafeCommand, sleep, spawnWithCleanEnv } from "../../util";
import {
  ABORT_AUTHORIZATION_FAILED_MESSAGE,
  AUTHORIZATION_FAILED_PATTERN,
  USER_NOT_IN_CACHE_PATTERN,
} from "./auth";
import { AzureSshRequest } from "./types";

const TUNNEL_READY_STRING = "Tunnel is ready";

// Ignore these debug messages from the tunnel process; they are far too noisy and spam the terminal with useless info
// anytime the SSH/SCP session has network activity.
const tunnelDebugOutputIgnorePatterns: RegExp[] = [
  /Waiting for (debugger|websocket) data/i,
  /Received (debugger|websocket)/i,
  /Sending to (debugger|websocket)/i,
];

export type BastionTunnelMeta = {
  killTunnel: () => Promise<void>;
  tunnelLocalPort: string;
};

export const azBastionTunnelCommand = (
  request: AzureSshRequest,
  port: string
) =>
  osSafeCommand("az", [
    "network",
    "bastion",
    "tunnel",
    "--ids",
    request.bastionId,
    "--target-resource-id",
    request.instanceId,
    "--resource-port",
    "22",
    "--port",
    port,
    // Always include the debug flag because we use the output to determine if we need
    // to reauthenticate the user when access fails. The output is silenced if the user
    // doesn't pass the --debug flag to the p0 ssh process.
    "--debug",
  ]);

const selectRandomPort = (): string => {
  // The IANA ephemeral port range is 49152 to 65535, inclusive. Pick a random value in that range.
  // If the port is in use (unlikely but possible), we can just generate a new value and try again.
  // 16384 is 65535 - 49152 + 1, the number of possible ports in the range.
  const port = Math.floor(Math.random() * 16384) + 49152;
  return port.toString();
};

const spawnBastionTunnelInBackground = (
  request: AzureSshRequest,
  port: string,
  options: { debug?: boolean; abortController: AbortController }
): Promise<BastionTunnelMeta> => {
  const { debug, abortController } = options;

  return new Promise<BastionTunnelMeta>((resolve, reject) => {
    let processSignalledToExit = false;
    let processExited = false;
    let stdout = "";
    let stderr = "";

    const { command, args } = azBastionTunnelCommand(request, port);

    if (debug) print2("Spawning Azure Bastion tunnel process...");

    // Spawn the process in detached mode so that it is in its own process group; this lets us kill it and all
    // descendent processes together.
    const child = spawnWithCleanEnv(command, args, {
      detached: true,
    });

    child.on("exit", (code) => {
      processExited = true;
      if (code === 0) {
        if (debug) print2("Azure Bastion tunnel process exited normally.");
        return;
      }

      if (!debug) {
        // stdout and stderr are printed in real-time when debugging is enabled, so we don't need to print them here
        print2(stdout);
        print2(stderr);
      }

      reject(
        `Error running Azure Network Bastion tunnel; tunnel process ended with status ${code}`
      );
    });

    child.on("error", (error: Error) => {
      if (debug) {
        print2(`Failed to run Azure Bastion tunnel: ${error.message}`);
      }
      return reject(`Failed to run Azure Bastion tunnel: ${error.message}`);
    });

    child.stdout.on("data", (data) => {
      const str = data.toString("utf-8");
      stdout += str;
      if (
        debug &&
        !tunnelDebugOutputIgnorePatterns.some((regex) => str.match(regex))
      ) {
        print2(str);
      }
    });

    child.stderr.on("data", (data) => {
      const str = data.toString("utf-8");
      stderr += str;
      if (
        debug &&
        !tunnelDebugOutputIgnorePatterns.some((regex) => str.match(regex))
      ) {
        print2(str);
      }

      // If we get a message indicating that the user's authorization is invalid, we need to terminate all of our connection attempts.
      if (AUTHORIZATION_FAILED_PATTERN.test(str)) {
        abortController.abort(ABORT_AUTHORIZATION_FAILED_MESSAGE);
      }

      if (USER_NOT_IN_CACHE_PATTERN.test(str)) {
        abortController.abort(ABORT_AUTHORIZATION_FAILED_MESSAGE);
      }

      if (str.includes(TUNNEL_READY_STRING)) {
        print2("Azure Bastion tunnel is ready.");

        resolve({
          killTunnel: async () => {
            if (processSignalledToExit || processExited) return;

            processSignalledToExit = true;

            if (child.pid) {
              // Kill the process and all its descendents via killing the process group; this is only possible
              // because we launched the process with `detached: true` above. This is necessary because `az` is
              // actually a bash script that spawns a Python process, and we need to kill the Python process as well.
              // SIGINT is equivalent to pressing Ctrl-C in the terminal; allows for the tunnel process to perform any
              // necessary cleanup of its own before exiting. The negative PID is what indicates that we want to kill
              // the whole process group.
              try {
                if (debug) {
                  print2(
                    `Sending SIGINT to Azure Bastion tunnel process (${child.pid})...`
                  );
                }
                process.kill(-child.pid, "SIGINT");

                // Give the tunnel a chance to quit gracefully after the SIGINT by waiting at least 250 ms and up to
                // 5 seconds. If the process is still running after that, it's probably hung; SIGKILL it to force it to
                // end immediately.
                const SPIN_WAIT_MS = 250;
                for (let spins = 0; spins < 20; spins++) {
                  await sleep(SPIN_WAIT_MS);

                  if (processExited) {
                    if (debug) {
                      print2(
                        `Azure Bastion tunnel process exited after SIGINT after ${spins * SPIN_WAIT_MS} ms.`
                      );
                    }
                    return;
                  }
                }

                if (debug) {
                  print2(
                    `Azure Bastion tunnel process (${child.pid}) not responding, sending SIGKILL...`
                  );
                }
                process.kill(-child.pid, "SIGKILL");
              } catch (error: any) {
                // Ignore the error and move on; we might as well just exit without waiting since we can't control
                // the child process, for whatever reason
                print2(`Failed to kill Azure Bastion tunnel process: ${error}`);
                child.unref();
              }
            }
          },
          tunnelLocalPort: port,
        });
      }
    });
  });
};

export const trySpawnBastionTunnel = async (
  request: AzureSshRequest,
  options: { abortController: AbortController; debug?: boolean }
): Promise<BastionTunnelMeta> => {
  // Attempt to spawn the tunnel SPAWN_TUNNEL_TRIES times, picking a new port each time. If we fail
  // too many times, then the problem is likely not the port, but something else.

  return await retryWithSleep(() =>
    spawnBastionTunnelInBackground(request, selectRandomPort(), options)
  );
};
