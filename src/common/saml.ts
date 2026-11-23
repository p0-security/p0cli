/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { parseXml } from "./xml";
import { flatten } from "lodash";

/** Gets the child element with this local name, whatever its namespace
 * prefix: Okta writes `saml2:`, PingFederate writes `saml:`. */
const child = (element: any, localName: string) =>
  element?.[
    Object.keys(element).find((key) => key.split(":").pop() === localName) ?? ""
  ];

/** Gets the values of an attribute of a base64 SAML response's assertion */
export const samlAttributeValues = (saml: string, name: string): string[] => {
  const samlText = Buffer.from(saml, "base64").toString("utf8");
  const statement = child(
    child(child(parseXml(samlText), "Response"), "Assertion"),
    "AttributeStatement"
  );
  const attribute = flatten([child(statement, "Attribute")]).find(
    (a: any) => a?._attributes.Name === name
  );
  return flatten([child(attribute, "AttributeValue") ?? []]);
};
