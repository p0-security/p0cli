/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { getOperatingSystem } from "../../util";

/**
 * Prepends with the operating-system specific method of
 * running a gcloud command.
 * @param args the arguments to be passed to gcloud (excluding "gcloud" itself)
 */
export const gcloudCommandArgs = (args: string[]) => {
  const isWindows = getOperatingSystem() === "win";

  // On Windows, when installing the Google Cloud tools, the main gcloud file is
  // a .cmd (shell script) file rather than a .exe (binary executable) file,
  // so when calling spawn, it cannot be located except via cmd.exe
  // Unlike in MacOS, the underlying Windows OS API that spawn uses doesn't
  // resolve .CMD files by default
  return isWindows
    ? { command: "cmd.exe", args: ["/d", "/s", "/c", "gcloud", ...args] }
    : { command: "gcloud", args };
};
