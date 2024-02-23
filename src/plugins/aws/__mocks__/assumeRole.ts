/** Copyright © 2024-present P0 Security 

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { AwsCredentials } from "../types";

export const assumeRoleWithSaml = async (): Promise<AwsCredentials> => ({
  AWS_ACCESS_KEY_ID: "test-access-key-id",
  AWS_SECRET_ACCESS_KEY: "test-secret-access-key",
  AWS_SESSION_TOKEN: "test-session-token",
});
