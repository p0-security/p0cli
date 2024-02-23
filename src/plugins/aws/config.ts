/** Copyright © 2024-present P0 Security 

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { doc } from "../../drivers/firestore";
import { Authn } from "../../types/identity";
import { AwsConfig } from "./types";
import { getDoc } from "firebase/firestore";

export const getAwsConfig = async (
  authn: Authn,
  account: string | undefined
) => {
  const { identity } = authn;
  const snapshot = await getDoc<AwsConfig, object>(
    doc(`o/${identity.org.tenantId}/integrations/aws`)
  );
  const config = snapshot.data();
  // TODO: Support alias lookup
  const item = account
    ? config?.workflows?.items.find(
        (i) => i.state === "installed" && i.account.id === account
      )
    : config?.workflows?.items[0];
  if (!item) throw `P0 is not installed on AWS account ${account}`;
  return { identity, config: item };
};
