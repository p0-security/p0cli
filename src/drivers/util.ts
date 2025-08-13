import { print2 } from "./stdio";

/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
export const EXPIRED_CREDENTIALS_MESSAGE =
  "Your credentials have expired. Please run `p0 login <organization>` to refresh your credentials.";

// 0x0A is utf-8 character code of line feed
const LINE_FEED = 10;
/**
 * Converts a string that contains newline-delimited JSON
 * to an array of parsed json objects
 */
export const convertJsonlToArray = <T>(array: Uint8Array, maxErrors = 5) => {
  const out: T[] = [];
  const decoder = new TextDecoder();
  let offset = 0;
  let numErrors = 0;
  const totalLength = array.length;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const ix = array.indexOf(LINE_FEED, offset);
    if (ix < 0) {
      break;
    }
    const slice = array.slice(offset, ix);
    const json = decoder.decode(slice);
    try {
      if (json) out.push(JSON.parse(json));
    } catch (error) {
      numErrors += 1;
      print2("Failed to parse JSON line: " + json);
      if (numErrors >= maxErrors) {
        throw "Can not read streaming data";
      }
    }
    if (ix >= 0) {
      offset = ix + 1;
    } else {
      break;
    }
  }
  const remainingSegments =
    offset >= 0 && offset < totalLength
      ? array.slice(offset)
      : new Uint8Array();
  return {
    segments: out,
    remainingSegments,
  };
};
