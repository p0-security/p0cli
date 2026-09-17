/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/

/** Prompts the user for an email/username and a masked password.
 *
 * This is a standalone, unwired prompt intended for a future interactive
 * login flow. It is not currently invoked by any command or plugin.
 */
export const promptForCredentials = async (): Promise<{
  email: string;
  password: string;
}> => {
  // inquirer v9+ is ESM-only and cannot be statically imported from
  // a CommonJS module, so a dynamic import is required here.
  const inquirer = (await import("inquirer")).default;
  const { email, password } = await inquirer.prompt([
    {
      type: "input",
      name: "email",
      message: "Email:",
    },
    {
      type: "password",
      name: "password",
      message: "Password:",
      mask: "*",
    },
  ]);
  return { email, password };
};
