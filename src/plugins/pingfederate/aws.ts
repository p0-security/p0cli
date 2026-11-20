/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { withRedirectServer } from "../../common/auth/server";
import { fetchIntegrationConfig } from "../../drivers/api";
import { print2 } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import { osSafeOpen } from "../../util";

// The P0 app's PingFederate install steps put this URL on the SP connection
// to AWS at this index, and the federation's pool roles trust this URL.
const SAML_PORT = 52702;
const SAML_PATH = "/saml";
const ACS_INDEX = 1;

type PingFederateAwsIamFederationConfig = {
  app: Record<string, { pingFederateUrl: string }>;
};

const startSsoUrl = (pingFederateUrl: string) =>
  `${pingFederateUrl.trim().replace(/\/+$/, "")}/idp/startSSO.ping?PartnerSpId=urn:amazon:webservices&ACSIdx=${ACS_INDEX}`;

/** Gets a base64 SAML response for AWS from a PingFederate app
 *
 * The user signs in to PingFederate in the browser, and PingFederate posts
 * the response to a local server.
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
  const url = startSsoUrl(app.pingFederateUrl);
  return await withRedirectServer<void, { SAMLResponse?: string }, string>(
    async () => {
      try {
        await osSafeOpen(url);
        print2("Sign in to PingFederate in the opened browser window.");
      } catch {
        print2(`Visit this URL to sign in to PingFederate:\n  ${url}`);
      }
    },
    async (_, { SAMLResponse }) => {
      if (!SAMLResponse) throw "PingFederate sent no SAML response.";
      return SAMLResponse;
    },
    { port: SAML_PORT, post: SAML_PATH }
  );
};
