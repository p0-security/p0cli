/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { fetchBreakGlassCredentials } from "../../drivers/api.js";
import { Authn } from "../../types/identity";
import { createTempDirectoryForKeys } from "../ssh/shared";
import { SELF_HOSTED_CERT_FILENAME } from "./ssh.js";
import * as fs from "fs/promises";
import path from "path";

export const breakGlassCredentials = async (
  authn: Authn,
  options: {
    requestId: string;
    abortController?: AbortController;
    debug?: boolean | undefined;
  }
) => {
  const { path: keyPath, cleanup: sshKeyPathCleanup } =
    await createTempDirectoryForKeys();
  const { privateKey, signedCertificate } = await fetchBreakGlassCredentials(
    authn,
    {
      requestId: options.requestId,
    }
  );

  const sshPrivateKeyPath = path.join(keyPath, "p0cli-break-glass-key");
  const sshCertificateKeyPath = path.join(keyPath, SELF_HOSTED_CERT_FILENAME);

  await fs.writeFile(sshPrivateKeyPath, privateKey, { mode: 0o600 });
  await fs.writeFile(sshCertificateKeyPath, signedCertificate);

  return {
    sshCertificateKeyPath,
    sshPrivateKeyPath,
    sshKeyPathCleanup,
  };
};
