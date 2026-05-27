/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

/** An entry in the new array-form delegation shape.
 *
 * The backend used to send delegation as a record (`{ aws: { ... } }`); it now
 * sends it as an array of `{ key, request }` entries. The `request` field holds
 * what used to be the record's value (permission, generated, nested delegation).
 */
export type DelegationEntry<K extends string, R> = {
  key: K;
  request: R;
};

/** Delegation field that tolerates both the legacy record form and the new
 * array form. Callers should not read this directly — use {@link getDelegate}.
 */
export type DelegationField<Old extends Record<string, any>> =
  | {
      [K in keyof Old & string]: DelegationEntry<K, Old[K]>;
    }[keyof Old & string][]
  | Old;

/** Resolve a delegate by key, accepting either the legacy record-form
 * delegation or the new array-form delegation.
 *
 * Returns the underlying delegate value (with `permission`, `generated`,
 * and nested `delegation` fields), or `undefined` if no entry matches.
 *
 * The generic shape (`K`, `V` rather than the full `Old` record) is
 * deliberate: matching the union `DelegationField<Old>` bidirectionally
 * confuses TS's inference and can lock `Old` onto the array branch.
 * Pinning `K` to the key argument and inferring `V` from the value avoids
 * that.
 */
export const getDelegate = <K extends string, V>(
  delegation:
    DelegationEntry<K, V>[] | { [P in K]?: V } | null | undefined,
  key: K
): V | undefined => {
  if (delegation == null) return undefined;
  if (Array.isArray(delegation)) {
    const entry = delegation.find((e) => e?.key === key);
    return entry?.request;
  }
  return delegation[key];
};
