/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import fs from "node:fs";
import net from "node:net";

const CONNECT_TIMEOUT_MS = 10000;
const RETRY_DELAY_MS = 250;
const MAX_ATTEMPTS = 60000 / RETRY_DELAY_MS; // Try for one minute

type SendFileOptions = {
  fileToSend: string;
  port: string;
  attemptsRemaining?: number;
};

/**
 * Writes a file to a port on localhost.
 *
 * Waits until the port is open by retrying  after a brief delay if the connection is refused.
 */
export const waitForLocalPortAndWriteFile = (
  options: SendFileOptions
): Promise<number | null> =>
  new Promise((resolve, reject) => {
    // TODO: read and write the file in chunks
    const data = fs.readFileSync(options.fileToSend);

    const client = net.createConnection(
      {
        timeout: CONNECT_TIMEOUT_MS,
        port: Number(options.port),
        host: "127.0.0.1",
      },
      () => {}
    );

    client.on("ready", () => {
      client.write(data);
      client.end();
    });

    client.on("error", (error) => {
      if ((error as any).code === "ECONNREFUSED") {
        const attemptsRemaining = options.attemptsRemaining || MAX_ATTEMPTS;
        if (attemptsRemaining > 0) {
          setTimeout(() => {
            waitForLocalPortAndWriteFile({
              ...options,
              attemptsRemaining: attemptsRemaining - 1,
            })
              .then(resolve)
              .catch(reject);
          }, RETRY_DELAY_MS);
        } else {
          reject(error);
        }
      } else {
        reject(error);
      }
    });

    client.on("close", () => {
      resolve(0);
    });
  });
