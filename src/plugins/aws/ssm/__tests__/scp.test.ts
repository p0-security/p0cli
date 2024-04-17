/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  detectPathType,
  isExplicitlyLocal,
  isRemoteWithColon,
  isRemoteWithUri,
} from "../scp";

describe("Path", () => {
  describe.each([
    [
      "path/to/file.zip",
      false,
      { isMatch: false },
      { isMatch: false },
      { type: "local", path: "path/to/file.zip" },
    ],
    [
      "/path/to/file.zip",
      true,
      { isMatch: false },
      { isMatch: false },
      { type: "local", path: "/path/to/file.zip" },
    ],
    [
      "./path/to/file.zip",
      true,
      { isMatch: false },
      { isMatch: false },
      { type: "local", path: "./path/to/file.zip" },
    ],
    [
      "../path/to/file.zip",
      true,
      { isMatch: false },
      { isMatch: false },
      { type: "local", path: "../path/to/file.zip" },
    ],
    [
      "host:/path/to/file.zip",
      false,
      { isMatch: true, host: "host:", path: "/path/to/file.zip" },
      { isMatch: false },
      { type: "remote", host: "host", path: "/path/to/file.zip" },
    ],
    [
      "host:/path/to:file.zip",
      false,
      { isMatch: true, host: "host:", path: "/path/to:file.zip" },
      { isMatch: false },
      { type: "remote", host: "host", path: "/path/to:file.zip" },
    ],
    [
      "host:path/to/file.zip",
      false,
      { isMatch: true, host: "host:", path: "path/to/file.zip" },
      { isMatch: false },
      { type: "remote", host: "host", path: "path/to/file.zip" },
    ],
    [
      "host:file.zip",
      false,
      { isMatch: true, host: "host:", path: "file.zip" },
      { isMatch: false },
      { type: "remote", host: "host", path: "file.zip" },
    ],
    [
      "host:",
      false,
      { isMatch: true, host: "host:", path: "" },
      { isMatch: false },
      { type: "remote", host: "host", path: "" },
    ],
    [
      "/path/with:colon/file.zip",
      true,
      { isMatch: true, host: "/path/with:", path: "colon/file.zip" },
      { isMatch: false },
      { type: "local", path: "/path/with:colon/file.zip" },
    ],
    [
      "./path/with:colon/file.zip",
      true,
      { isMatch: true, host: "./path/with:", path: "colon/file.zip" },
      { isMatch: false },
      { type: "local", path: "./path/with:colon/file.zip" },
    ],
    [
      "../path/with:colon/file.zip",
      true,
      { isMatch: true, host: "../path/with:", path: "colon/file.zip" },
      { isMatch: false },
      { type: "local", path: "../path/with:colon/file.zip" },
    ],
    [
      "scp://host:1234/path/to/file.zip",
      false,
      { isMatch: false },
      { isMatch: true, host: "host", port: ":1234", path: "/path/to/file.zip" },
      { type: "remote", host: "host", port: "1234", path: "/path/to/file.zip" },
    ],
    [
      "scp://host:/path/to/file.zip",
      false,
      { isMatch: false },
      { isMatch: true, host: "host", port: ":", path: "/path/to/file.zip" },
      { type: "remote", host: "host", port: "", path: "/path/to/file.zip" },
    ],
    [
      "scp://host:path/to/file.zip",
      false,
      { isMatch: false },
      { isMatch: true, host: "host", port: ":", path: "path/to/file.zip" },
      { type: "remote", host: "host", port: "", path: "path/to/file.zip" },
    ],
    [
      "scp://host/path/to/file.zip",
      false,
      { isMatch: false },
      { isMatch: true, host: "host", port: "", path: "/path/to/file.zip" },
      { type: "remote", host: "host", port: "", path: "/path/to/file.zip" },
    ],
    [
      "scp://host",
      false,
      { isMatch: false },
      { isMatch: true, host: "host", port: "", path: "" },
      { type: "remote", host: "host", port: "", path: "" },
    ],
    [
      "scp://host:",
      false,
      { isMatch: false },
      { isMatch: true, host: "host", port: ":", path: "" },
      { type: "remote", host: "host", port: "", path: "" },
    ],
    [
      "scp://host/",
      false,
      { isMatch: false },
      { isMatch: true, host: "host", port: "", path: "/" },
      { type: "remote", host: "host", port: "", path: "/" },
    ],
  ])(
    "%s should match expectation",
    (
      path,
      expectedIsLocal,
      expectedIsRemoteWithColon,
      expectedIsRemoteWithUri,
      expectedPathType
    ) => {
      it("when tested for isExplicitlyLocal", () => {
        const result = isExplicitlyLocal(path);
        expect(result).toEqual(expectedIsLocal);
      });
      it("when tested for isRemoteWithColon", () => {
        const result = isRemoteWithColon(path);
        expect(result).toEqual(expectedIsRemoteWithColon);
      });
      it("when tested for isRemoteWithUri", () => {
        const result = isRemoteWithUri(path);
        expect(result).toEqual(expectedIsRemoteWithUri);
      });
      it("when tested for detectPathType", () => {
        const result = detectPathType(path);
        expect(result).toEqual(expectedPathType);
      });
    }
  );
});
