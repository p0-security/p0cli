/** Copyright © 2024 P0 Security 

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/

/** Converts object data to a URL encoded form */
export const urlEncode = (data: Record<string, string>) =>
  Object.entries(data)
    .map((kv) => kv.map(encodeURIComponent).join("="))
    .join("&");

/** Validates an HTTP response, throwing a friendly
 *  error message if invalid
 */
export const validateResponse = async (response: Response) => {
  if (response.ok) return response;
  throw new Error(`Error in fetch request to ${response.url.split("?")[0]}:
${response.status} ${response.statusText}

${await response.text()}`);
};
