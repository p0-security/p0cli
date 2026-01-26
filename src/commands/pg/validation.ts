/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { asyncSpawn } from "../../common/subprocess";
import { print2 } from "../../drivers/stdio";
import { sys } from "typescript";

/**
 * Validates that all required CLI tools are installed and available in PATH
 * This is called early, before authentication, so we check all possible tools
 * based on the mode (psql or url).
 *
 * @param psqlMode - Whether we're in psql mode (requires psql) or url mode (prints connection details)
 * @param debug - Whether to print debug information
 * @throws Exits with code 1 if any required tool is not found
 */
export const validatePgTools = async (
    psqlMode: boolean,
    debug?: boolean
): Promise<void> => {
    const tools: Array<{ name: string; description: string }> = [];

    if (psqlMode) {
        tools.push({ name: "psql", description: "PostgreSQL client" });
    }
    // URL mode doesn't require any specific tools - we just print connection details

    // Always check AWS and gcloud CLI (we don't know provider yet)
    tools.push(
        { name: "aws", description: "AWS CLI" },
        { name: "gcloud", description: "Google Cloud CLI" }
    );

    for (const tool of tools) {
        try {
            // Use 'where' on Windows or 'which' on Unix
            const checkCommand = process.platform === "win32" ? "where" : "which";
            await asyncSpawn({ debug }, checkCommand, [tool.name]);
        } catch {
            print2(`Error: ${tool.description} (${tool.name}) not found in PATH.`);
            print2(
                `Please install ${tool.description} and ensure it's in your PATH.`
            );
            sys.exit(1);
        }
    }
};

/**
 * Validates that required CLI tools are installed and available in PATH
 * This is a legacy function kept for backward compatibility, but validatePgTools
 * should be used instead for early validation.
 *
 * @param provider - The cloud provider ("aws" or "gcp") to determine which tools to check
 * @param debug - Whether to print debug information
 * @throws Exits with code 1 if any required tool is not found
 */
export const validateCliTools = async (
    provider?: "aws" | "gcp",
    debug?: boolean
): Promise<void> => {
    const tools: Array<{ name: string; description: string }> = [
        { name: "psql", description: "PostgreSQL client" },
    ];

    // Add provider-specific tools
    if (provider === "gcp") {
        tools.push({ name: "gcloud", description: "Google Cloud CLI" });
    } else {
        // Default to AWS if not specified
        tools.push({ name: "aws", description: "AWS CLI" });
    }

    for (const tool of tools) {
        try {
            // Use 'command -v' on Unix or 'where' on Windows, but 'which' works on most systems
            const checkCommand = process.platform === "win32" ? "where" : "which";
            await asyncSpawn({ debug }, checkCommand, [tool.name]);
        } catch {
            print2(`Error: ${tool.description} (${tool.name}) not found in PATH.`);
            print2(
                `Please install ${tool.description} and ensure it's in your PATH.`
            );
            sys.exit(1);
        }
    }
};
