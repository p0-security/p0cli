/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authenticate } from "../../drivers/auth";
import { print2 } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import { getAppName } from "../../util";
import {
    configureAwsSsoProfile,
    connectToDatabase,
    generateDbAuthTokenWithAutoLogin,
    getRdsEndpoint,
    printAwsConnectionDetails,
} from "./aws";
import {
    extractConnectionDetails,
    getUserEmail,
    provisionRequest,
} from "./connection";
import { connectToCloudSQL, printGcpConnectionDetails } from "./gcp";
import { ConnectionDetails, PgCommandArgs } from "./types";
import { validatePgTools } from "./validation";
import { sys } from "typescript";
import yargs from "yargs";

/**
 * The pg command for connecting to PostgreSQL databases
 */
export const pgCommand = (yargs: yargs.Argv) =>
    yargs.command<PgCommandArgs>(
        "pg <destination>",
        "Connect to a Postgres database or get connection details (AWS RDS or GCP CloudSQL)",
        (yargs) =>
            yargs
                .positional("destination", {
                    type: "string",
                    demandOption: true,
                    describe: "The RDS Postgres instance name",
                })
                .option("role", {
                    type: "string",
                    demandOption: true,
                    describe: "The IAM role name to use (AWS SSO role or GCP IAM role)",
                })
                .option("psql", {
                    type: "boolean",
                    describe: "Connect interactively using psql",
                    default: false,
                })
                .option("url", {
                    type: "boolean",
                    describe: "Get connection URL and details",
                    default: false,
                })
                .option("reason", {
                    describe: "Reason access is needed",
                    type: "string",
                })
                .option("duration", {
                    type: "string",
                    describe:
                        "Requested duration for access (format like '10 minutes', '2 hours', '5 days', or '1 week')",
                })
                .option("debug", {
                    type: "boolean",
                    describe: "Print debug information.",
                    default: false,
                })
                .option("ssl", {
                    type: "boolean",
                    describe: "Enable SSL/TLS for database connections (recommended for AWS RDS, optional for GCP with Cloud SQL Proxy)",
                    default: false,
                })
                .check((argv) => {
                    if (!argv.psql && !argv.url) {
                        throw new Error("Must specify either --psql or --url");
                    }
                    if (argv.psql && argv.url) {
                        throw new Error("Cannot specify both --psql and --url");
                    }
                    return true;
                })
                .usage("$0 pg <destination> --role <ROLE_NAME> --psql|--url")
                .epilogue(
                    `Connect to a Postgres database or get connection details with IAM authentication.

Supports both AWS RDS and GCP CloudSQL instances. The command automatically
detects the provider and uses the appropriate authentication method.

Use --psql to connect interactively using the psql command-line client.
Use --url to get connection details and postgresql:// URL for use with any client.

To list available instances:
  $ ${getAppName()} ls pg role instance

For AWS RDS:
  - Uses AWS SSO IAM database authentication
  - Automatically configures AWS SSO and generates IAM auth tokens

For GCP CloudSQL:
  - Uses Cloud SQL Proxy for secure connections
  - Supports both private and public IP instances
  - Uses IAM-based authentication

Examples:
  $ ${getAppName()} pg my-rds-instance --role MyRole --psql --reason "Need to debug production issue"
  $ ${getAppName()} pg my-rds-instance --role MyRole --url --reason "Need connection details"`
                ),
        pgAction
    );

/**
 * Connect to a Postgres database or get connection details
 *
 * Implicitly requests access to the database if not already granted.
 * Supports both AWS RDS and GCP CloudSQL instances.
 *
 * With --psql: Connects interactively using psql
 * With --url: Provides connection URL and details for use with any client
 */
const pgAction = async (args: yargs.ArgumentsCamelCase<PgCommandArgs>) => {
    // Validate all required tools BEFORE authentication/request
    await validatePgTools(args.psql || false, args.debug);

    let authn: Authn;
    try {
        authn = await authenticate(args);
    } catch (error) {
        print2("Error: Failed to authenticate. Please ensure you are logged in.");
        if (args.debug && error instanceof Error) {
            print2(`Details: ${error.message}`);
        }
        sys.exit(1);
        throw new Error("Unreachable");
    }

    // Make request and wait for approval
    const requestArgs = args.url
        ? { ...args, reason: args.reason || "Lab Postgres connection" }
        : args;
    let response: Awaited<ReturnType<typeof provisionRequest>>;
    try {
        response = await provisionRequest(authn!, requestArgs);
    } catch (error) {
        print2("Error: Failed to provision database access request.");
        if (args.debug && error instanceof Error) {
            print2(`Details: ${error.message}`);
        }
        sys.exit(1);
        throw new Error("Unreachable");
    }
    if (!response || !response.request) {
        print2("Error: Failed to provision database access request.");
        sys.exit(1);
        throw new Error("Unreachable");
    }

    const provisionedRequest = response!.request!;

    // Get user email for database username
    let dbUserResult: string | null;
    try {
        dbUserResult = await getUserEmail(authn!, provisionedRequest, args.debug);
    } catch (error) {
        print2("Error: Failed to determine database username.");
        if (args.debug && error instanceof Error) {
            print2(`Details: ${error.message}`);
        }
        sys.exit(1);
        throw new Error("Unreachable");
    }
    if (!dbUserResult) {
        print2(
            "Error: Could not determine user email for database authentication."
        );
        print2("Please ensure your user account has a valid email address.");
        sys.exit(1);
        throw new Error("Unreachable");
    }
    const dbUser: string = dbUserResult!;

    // Extract connection details from the request
    let connectionDetailsResult: ConnectionDetails | null;
    try {
        connectionDetailsResult = await extractConnectionDetails(
            provisionedRequest,
            args.role,
            args.debug,
            authn!,
            args
        );
    } catch (error) {
        print2(
            "Error: Failed to extract connection details from request response."
        );
        if (args.debug && error instanceof Error) {
            print2(`Details: ${error.message}`);
        }
        sys.exit(1);
        throw new Error("Unreachable");
    }
    if (!connectionDetailsResult) {
        print2(
            "Error: Could not extract connection details from request response."
        );
        print2("The request may be missing required connection information.");
        sys.exit(1);
        throw new Error("Unreachable");
    }
    const connectionDetails: ConnectionDetails = connectionDetailsResult!;

    // Route to provider-specific connection flow based on mode
    try {
        if (args.url) {
            // URL mode: provide connection details
            if (connectionDetails.provider === "gcp") {
                await printGcpConnectionDetails(connectionDetails, dbUser, args.ssl, args.debug);
            } else {
                // AWS RDS URL mode
                let profileName: string;
                try {
                    profileName = await configureAwsSsoProfile(
                        connectionDetails,
                        args.debug
                    );
                } catch (error) {
                    print2("Error: Failed to configure AWS SSO profile.");
                    if (args.debug && error instanceof Error) {
                        print2(`Details: ${error.message}`);
                    }
                    sys.exit(1);
                    throw new Error("Unreachable");
                }



                const hostParts = connectionDetails.rdsHost.split(".");
                const isConstructedEndpoint =
                    hostParts.length === 4 &&
                    hostParts[1] === connectionDetails.region &&
                    hostParts[2] === "rds" &&
                    hostParts[3] === "amazonaws.com";

                if (isConstructedEndpoint) {
                    const instanceIdentifier =
                        hostParts[0] || connectionDetails.rdsHost;
                    const actualRdsHost = await getRdsEndpoint(
                        instanceIdentifier,
                        connectionDetails.region,
                        profileName!,
                        args.debug
                    );
                    if (actualRdsHost && actualRdsHost !== connectionDetails.rdsHost) {
                        connectionDetails.rdsHost = actualRdsHost;
                        if (args.debug) {
                            print2(`Updated RDS endpoint to: ${actualRdsHost}`);
                        }
                    }
                }

                let token: string;
                try {
                    token = await generateDbAuthTokenWithAutoLogin(
                        connectionDetails,
                        dbUser,
                        profileName!,
                        args.debug
                    );
                } catch (error) {
                    print2("Error: Failed to generate database authentication token.");
                    if (args.debug && error instanceof Error) {
                        print2(`Details: ${error.message}`);
                    }
                    sys.exit(1);
                    throw new Error("Unreachable");
                }

                try {
                    await printAwsConnectionDetails(
                        connectionDetails,
                        dbUser,
                        token!,
                        args.ssl,
                        args.debug
                    );
                } catch (error) {
                    print2("Error: Failed to print connection details.");
                    if (args.debug && error instanceof Error) {
                        print2(`Details: ${error.message}`);
                    }
                    sys.exit(1);
                }

                if (process.env.NODE_ENV !== "unit") {
                    process.exit(0);
                }
            }
        } else {
            // psql mode: connect interactively
            if (connectionDetails.provider === "gcp") {
                await connectToCloudSQL(connectionDetails, dbUser, args.ssl, args.debug);
            } else {
                // AWS RDS connection flow
                let profileName: string;
                try {
                    profileName = await configureAwsSsoProfile(
                        connectionDetails,
                        args.debug
                    );
                } catch (error) {
                    print2("Error: Failed to configure AWS SSO profile.");
                    if (args.debug && error instanceof Error) {
                        print2(`Details: ${error.message}`);
                    }
                    sys.exit(1);
                    throw new Error("Unreachable");
                }



                // Get actual RDS endpoint if needed
                const hostParts = connectionDetails.rdsHost.split(".");
                const isConstructedEndpoint =
                    hostParts.length === 4 &&
                    hostParts[1] === connectionDetails.region &&
                    hostParts[2] === "rds" &&
                    hostParts[3] === "amazonaws.com";

                if (isConstructedEndpoint) {
                    const instanceIdentifier =
                        hostParts[0] || connectionDetails.rdsHost;
                    const actualRdsHost = await getRdsEndpoint(
                        instanceIdentifier,
                        connectionDetails.region,
                        profileName!,
                        args.debug
                    );
                    if (actualRdsHost && actualRdsHost !== connectionDetails.rdsHost) {
                        connectionDetails.rdsHost = actualRdsHost;
                        if (args.debug) {
                            print2(`Updated RDS endpoint to: ${actualRdsHost}`);
                        }
                    }
                } else {
                    if (args.debug) {
                        print2(
                            `Using RDS endpoint from integration config: ${connectionDetails.rdsHost}`
                        );
                    }
                }

                // Generate IAM auth token (with automatic SSO login if needed)
                let token: string;
                try {
                    token = await generateDbAuthTokenWithAutoLogin(
                        connectionDetails,
                        dbUser,
                        profileName!,
                        args.debug
                    );
                } catch (error) {
                    print2("Error: Failed to generate database authentication token.");
                    if (args.debug && error instanceof Error) {
                        print2(`Details: ${error.message}`);
                    }
                    sys.exit(1);
                    throw new Error("Unreachable");
                }

                // Connect to database
                try {
                    await connectToDatabase(connectionDetails, dbUser, token!, args.ssl, args.debug);
                } catch (error) {
                    print2("Error: Failed to connect to database.");
                    if (args.debug && error instanceof Error) {
                        print2(`Details: ${error.message}`);
                    }
                    sys.exit(1);
                }
            }
        }
    } catch (error) {
        print2("Error: Failed to establish database connection.");
        if (args.debug && error instanceof Error) {
            print2(`Details: ${error.message}`);
            if (error.stack) {
                print2(`Stack: ${error.stack}`);
            }
        }
        sys.exit(1);
    }

    // Force exit to prevent hanging
    if (process.env.NODE_ENV !== "unit") {
        process.exit(0);
    }
};
