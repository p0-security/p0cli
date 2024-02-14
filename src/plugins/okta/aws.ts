import { initOktaSaml } from "../../commands/aws/role";
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
      return await assumeRoleWithSaml({
        account,
        role: args.role,
        saml: {
          providerName: config.uidLocation.samlProviderName,
          response: samlResponse,
        },
      });
    },
    { duration: 3600e3 }
  );
