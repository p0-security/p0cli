/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import tmp from "tmp-promise";

export const createTempDirectoryForKeys = async (): Promise<{
  path: string;
  cleanup: () => Promise<void>;
}> => {
  // unsafeCleanup lets us delete the directory even if there are still files in it, which is fine since the
  // files are no longer needed once we've authenticated to the remote system.
  const { path, cleanup } = await tmp.dir({
    mode: 0o700,
    prefix: "p0cli-",
    unsafeCleanup: true,
  });

  return { path, cleanup };
};
