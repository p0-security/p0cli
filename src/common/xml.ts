/** Copyright © 2024-present P0 Security 

This file is part of @p0security/p0cli

@p0security/p0cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/p0cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/p0cli. If not, see <https://www.gnu.org/licenses/>.
**/
// Avoid XXE and friends with a (best-as-we-know) safe XML parser
import { parseXml as libParse, XmlElement } from "@rgrove/parse-xml";
import { groupBy, mapValues } from "lodash";

const isXmlElement = (node: any): node is XmlElement =>
  node instanceof XmlElement;

const elementToObject = (el: XmlElement): any => {
  if (el.children.find((n) => n instanceof XmlElement)) {
    const object = mapValues(
      groupBy(el.children.filter(isXmlElement), (el) => el.name),
      (items) =>
        items.length === 1
          ? elementToObject(items[0]!)
          : items.map(elementToObject)
    );
    Object.assign(object, { _attributes: { ...el.attributes } });
    return object;
  }
  return el.text.trim();
};

/** A janky XML document -> POJS parser
 *
 * The document is treated as an XML element, then transformed
 * recursively via the following rules:
 *
 * If the element has child elements, it is converted to an object
 * with a property for each unique child element name, with
 * the property value equal to:
 * - The child element's transformed value, if there is only
 *   one element with the property name
 * - An array of transformed elements, if there are multiple
 *   child elements with the property name
 *
 * In addition, when the element has children, it receives an
 * additional `_attributes` property, which is an object of the
 * element's attributes.
 *
 * Otherwise, the element is transformed into the element's XML
 * text.
 */
export const parseXml = (xml: string) => {
  const parsed = libParse(xml);
  return elementToObject(parsed as any as XmlElement);
};
