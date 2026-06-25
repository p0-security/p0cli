/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

/** An entry in the array-form delegation shape: an array of `{ key, request }`
 * entries, where `request` holds the delegate value (permission, generated,
 * nested delegation) and key is what type i.e 'aws.
 */
export type DelegationEntry<K extends string, R> = {
  key: K;
  request: R;
};

/** Array-form delegation. Callers should not read this directly — use
 * {@link getDelegate}.
 */
export type DelegationField<Spec extends Record<string, any>> = {
  [K in keyof Spec & string]: DelegationEntry<K, Spec[K]>;
}[keyof Spec & string][];

/** Resolve a delegate by key from array-form delegation.
 *
 * Returns the underlying delegate value (with `permission`, `generated`,
 * and nested `delegation` fields), or `undefined` if no entry matches.
 *
 * Keyed on the whole `Spec` and indexed by `key`, so `getDelegate(d, "aws")`
 * returns exactly `Spec["aws"]` — no union, no caller-side narrowing, even for
 * multi-key delegations. The type-guard `find` asserts that the entry matching
 * `key` carries `Spec[K]` (the runtime key check is the proof). The `Spec`
 * default keeps nullish-input calls compiling when there is nothing to infer.
 */
export const getDelegate = <
  Spec extends Record<string, any> = Record<string, any>,
  K extends keyof Spec & string = keyof Spec & string,
>(
  delegation: DelegationField<Spec> | null | undefined,
  key: K
): (Spec[K] & { type: K }) | undefined => {
  const request = delegation?.find(
    (e): e is DelegationEntry<K, Spec[K]> => e?.key === key
  )?.request;
  if (!request) return undefined;

  return { ...request, type: key };
};
