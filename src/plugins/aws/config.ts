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
