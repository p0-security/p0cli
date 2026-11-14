/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** The P0 gateway's MCP server URL without a trailing slash, query or
 * fragment. Throws for a URL that is not HTTPS, except on a loopback host. */
export function normalizeServerUrl(serverUrl: string): string {
  const url = new URL(serverUrl);
  const allowed =
    url.protocol === "https:" ||
    (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname));
  if (!allowed) throw `The server URL must use HTTPS: ${serverUrl}`;
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

/** Throws when `url` is not on the origin of `serverUrl`. */
export function assertSameOrigin(serverUrl: string, url: string) {
  if (new URL(url).origin !== new URL(serverUrl).origin) {
    throw `The P0 gateway metadata points to another origin: ${url}`;
  }
}
