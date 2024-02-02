import { authenticate, loadCredentials } from "../../drivers/auth";
import { doc } from "../../drivers/firestore";
import { AwsConfig } from "./types";
import { getDoc } from "firebase/firestore";

export const getAwsConfig = async (account: string | undefined) => {
  const identity = await loadCredentials();
  await authenticate();
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
