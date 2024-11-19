/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { retryWithSleep } from "../../common/retry";
import { print2 } from "../../drivers/stdio";
import { AzureSshRequest } from "./types";
import { azureRequestToResourceId } from "./util";
import { spawn } from "node:child_process";

const TUNNEL_READY_STRING = "Tunnel is ready";
const SPAWN_TUNNEL_TRIES = 3;

export type BastionTunnelMeta = {
  killTunnel: () => void;
  tunnelLocalPort: string;
};

const selectRandomPort = (): string => {
  // The IANA ephemeral port range is 49152 to 65535, inclusive. Pick a random value in that range.
  // If the port is in use (unlikely but possible), we can just generate a new value and try again.
  // 16384 is 65535 - 49152 + 1, the number of possible ports in the range.
  const port = Math.floor(Math.random() * 16384) + 49152;
  return port.toString();
};

const spawnBastionTunnelInBackground = (
  request: AzureSshRequest,
  port: string
): Promise<BastionTunnelMeta> => {
  return new Promise<BastionTunnelMeta>((resolve, reject) => {
    const child = spawn("az", [
      "network",
      "bastion",
      "tunnel",
      "--name",
      request.bastionName,
      "--resource-group",
      request.bastionResourceGroup,
      "--target-resource-id",
      azureRequestToResourceId(request),
      "--resource-port",
      "22",
      "--port",
      port,
    ]);

    const exitListener = child.on("exit", (code) => {
      exitListener.unref();
      // We don't expect the process to terminate on its own, so this almost always is an error
      reject(`Bastion tunnel process exited with code ${code}`);
    });

    child.stdout.on("data", (data) => {
      const str = data.toString("utf-8");

      if (str.includes(TUNNEL_READY_STRING)) {
        exitListener.unref();
        resolve({
          killTunnel: () => {
            if (processTerminated) return;

            processTerminated = true;

            if (child.pid) {
              // Kill the process and all its descendents via killing the process group; this is only possible
              // because we launched the process with `detached: true` above. This is necessary because `az` is
              // actually a bash script that spawns a Python process, and we need to kill the Python process as well.
              // SIGINT is equivalent to pressing Ctrl-C in the terminal; allows for the tunnel process to perform any
              // necessary cleanup of its own before exiting. The negative PID is what indicates that we want to kill
              // the whole process group.
              process.kill(-child.pid, "SIGINT");
            }

            child.unref();
          },
          tunnelLocalPort: port,
        });
      }

      print2(str);
    });

    child.stderr.on("data", (data) => {
      const str = data.toString("utf-8");
      print2(str);
    });
  });
};

export const trySpawnBastionTunnel = async (
  request: AzureSshRequest
): Promise<BastionTunnelMeta> => {
  // Attempt to spawn the tunnel SPAWN_TUNNEL_TRIES times, picking a new port each time. If we fail
  // too many times, then the problem is likely not the port, but something else.

  return await retryWithSleep(
    () => spawnBastionTunnelInBackground(request, selectRandomPort()),
    () => true,
    SPAWN_TUNNEL_TRIES,
    1000
  );
};
