/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { withRedirectServer } from "../../common/auth/server";
import { samlAttributeValues } from "../../common/saml";
import { fetchIntegrationConfig } from "../../drivers/api";
import { print2 } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import { osSafeOpen } from "../../util";
import { randomBytes } from "node:crypto";

// The P0 app's PingFederate install steps put this URL on the SP connection
// to AWS at this index, and the federation's pool roles trust this URL.
const SAML_HOST = "127.0.0.1";
const SAML_PORT = 52702;
const SAML_PATH = "/saml";
const ACS_INDEX = 1;

type PingFederateAwsIamFederationConfig = {
  app: Record<string, { pingFederateUrl: string }>;
};

const SOURCE_IDENTITY_ATTRIBUTE =
  "https://aws.amazon.com/SAML/Attributes/SourceIdentity";

// PingFederate returns `TargetResource` as the response's `RelayState`
const startSsoUrl = (pingFederateUrl: string, nonce: string) =>
  `${pingFederateUrl.trim().replace(/\/+$/, "")}/idp/startSSO.ping?PartnerSpId=urn:amazon:webservices&ACSIdx=${ACS_INDEX}&TargetResource=${nonce}`;

/** Gets the email of the user who is signed in to P0 */
const userEmail = (authn: Authn): string | undefined => {
  const firebaseEmail = authn.userCredential?.user.email;
  if (firebaseEmail) return firebaseEmail;
  const payload = authn.identity.credential.id_token?.split(".")[1];
  return payload
    ? JSON.parse(Buffer.from(payload, "base64url").toString()).email
    : undefined;
};

/** Gets a base64 SAML response for AWS from a PingFederate app
 *
 * The user signs in to PingFederate in the browser, and PingFederate posts
 * the response to a local server. The server accepts only the response to this
 * sign-in, for the user who is signed in to P0.
 */
export const fetchPingFederateSamlForAws = async (
  authn: Authn,
  appId: string,
  debug?: boolean
) => {
  const { config } = await fetchIntegrationConfig<{
    config: PingFederateAwsIamFederationConfig;
  }>(authn, "pingfederate-aws-iam-federation", debug);
  const app = config?.app?.[appId];
  if (!app) throw `PingFederate app ${appId} is not installed.`;
  const email = userEmail(authn);
  if (!email) throw "Can't find your email to check PingFederate's response.";
  const nonce = randomBytes(32).toString("hex");
  const url = startSsoUrl(app.pingFederateUrl, nonce);
  return await withRedirectServer<
    void,
    { RelayState?: string; SAMLResponse?: string },
    string
  >(
    async () => {
      try {
        await osSafeOpen(url);
        print2("Sign in to PingFederate in the opened browser window.");
      } catch {
        print2(`Visit this URL to sign in to PingFederate:\n  ${url}`);
      }
    },
    async (_, { RelayState, SAMLResponse }) => {
      if (RelayState !== nonce)
        throw "The SAML response isn't from this sign-in.";
      if (!SAMLResponse) throw "PingFederate sent no SAML response.";
      const [sourceIdentity] = samlAttributeValues(
        SAMLResponse,
        SOURCE_IDENTITY_ATTRIBUTE
      );
      if (sourceIdentity?.toLowerCase() !== email.toLowerCase())
        throw `PingFederate signed in ${sourceIdentity ?? "a user without a SourceIdentity"}, not ${email}.`;
      return SAMLResponse;
    },
    { host: SAML_HOST, port: SAML_PORT, post: SAML_PATH }
  );
};
