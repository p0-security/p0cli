/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { mapValues } from "lodash";

const AnsiCodes = {
  Reset: "00",
  Dim: "02",
  Green: "32",
  Yellow: "33",
} as const;

export const Ansi = (value: string) => `\u001b[${value}`;

/** Creates an ANSI Select Graphic Rendition code */
export const AnsiSgr = mapValues(AnsiCodes, (v) => Ansi(v + "m"));
