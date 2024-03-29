/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { initOktaSaml, rolesFromSaml } from "../../commands/aws/role";
import { cached } from "../../drivers/auth";
import { Authn } from "../../types/identity";
import { assumeRoleWithSaml } from "../aws/assumeRole";

export const assumeRoleWithOktaSaml = async (
  authn: Authn,
  args: { account?: string; role: string }
) =>
  await cached(
    `aws-okta-${args.account}-${args.role}`,
    async () => {
      const { account, config, samlResponse } = await initOktaSaml(
        authn,
        args.account
      );
      const { roles } = rolesFromSaml(account, samlResponse);
      if (!roles.includes(args.role))
        throw `Role not available. Available roles:\n${roles.map((r) => `  ${r}`).join("\n")}`;
      return await assumeRoleWithSaml({
        account,
        role: args.role,
        saml: {
          providerName: config.login.provider.identityProvider,
          response: samlResponse,
        },
      });
    },
    { duration: 3600e3 }
  );
