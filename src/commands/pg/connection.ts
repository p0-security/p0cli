/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { print2 } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import { PsqlCommandArgs, PsqlPermissionSpec } from "../../types/psql";
import { PermissionRequest } from "../../types/request";
import { decodeProvisionStatus } from "../shared";
import { request } from "../shared/request";
import { extractAwsConnectionDetails } from "./aws";
import { extractGcpConnectionDetails } from "./gcp";
import { ConnectionDetails } from "./types";
import { pick } from "lodash";
import yargs from "yargs";

/**
 * Determines the database username to use for authentication
 *
 * Tries multiple sources in order:
 * 1. Username from request.generated.username (backend-provided)
 * 2. User email from authentication credentials
 * 3. Principal field from the request
 *
 * @param authn - Authentication credentials containing user information
 * @param request - The permission request that may contain username information
 * @param debug - Whether to print debug information about which source was used
 * @returns The database username, or null if none could be determined
 */
export const getUserEmail = async (
  authn: Authn,
  request?: PermissionRequest<PsqlPermissionSpec>,
  debug?: boolean
): Promise<string | null> => {
  // First, check if the backend provided username in the generated field
  if (request?.generated?.username) {
    if (debug) {
      print2(`Using username from request: ${request.generated.username}`);
    }
    return request.generated.username;
  }

  // Fallback to user email from authentication
  if (authn.userCredential?.user?.email) {
    if (debug) {
      print2(`Using user email: ${authn.userCredential.user.email}`);
    }
    return authn.userCredential.user.email;
  }

  // Try to extract from principal field in request
  if (request?.principal) {
    if (debug) {
      print2(`Using principal from request: ${request.principal}`);
    }
    return request.principal;
  }

  if (debug) {
    print2("Could not determine username for database authentication");
  }
  return null;
};

/**
 * Requests access to the Postgres database and waits for approval
 *
 * Makes a request to the backend for database access and waits for it to be
 * provisioned. Handles both new requests and pre-existing access.
 *
 * @param authn - Authentication credentials
 * @param args - Command arguments including destination, role, reason, and duration
 * @returns The provisioned request response, or null if provisioning failed
 */
export const provisionRequest = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<PsqlCommandArgs>
): Promise<{ request: PermissionRequest<PsqlPermissionSpec> } | null> => {
  const { destination, role } = args;

  const makeRequest = async () => {
    return await request("request")<PermissionRequest<PsqlPermissionSpec>>(
      {
        ...pick(args, "$0", "_"),
        arguments: [
          "pg",
          "role",
          destination,
          role,
          ...(args.reason ? ["--reason", args.reason] : []),
          ...(args.duration ? ["--duration", args.duration] : []),
        ],
        wait: true,
        debug: args.debug,
      },
      authn,
      { message: "approval-required" }
    );
  };

  const response = await makeRequest();

  if (!response) {
    print2("Did not receive access ID from server");
    return null;
  }

  const { isPreexisting } = response;

  const message = isPreexisting
    ? "Existing access found. Connecting to database."
    : "Waiting for access to be provisioned";
  print2(message);

  const result = await decodeProvisionStatus<PsqlPermissionSpec>(
    response.request
  );

  if (!result) {
    // Check if the error is about public IP requirement for CloudSQL
    const errorMessage = response.request?.error?.message || "";
    if (
      errorMessage.includes("does not have a public IP address") &&
      errorMessage.includes("Cloud SQL")
    ) {
      print2("");
      print2(
        "Note: The Cloud SQL Proxy (which this CLI uses) supports private IP instances."
      );
      print2(
        "This error is due to a backend limitation that requires a public IP."
      );
      print2(
        "Please contact your P0 administrator to update the backend to support private IP CloudSQL instances."
      );
    }
    return null;
  }

  return {
    request: response.request,
  };
};

/**
 * Extracts connection details from the permission request response
 *
 * Detects the cloud provider (AWS RDS or GCP CloudSQL) and extracts
 * provider-specific connection information. Routes to provider-specific
 * extraction functions based on the detected provider.
 *
 * @param request - The permission request response containing connection details
 * @param roleName - The IAM role name to use (for AWS)
 * @param debug - Whether to print debug information
 * @param authn - Authentication credentials (used for querying backend if needed)
 * @param args - Command arguments (used for querying backend if needed)
 * @returns Connection details for the detected provider, or null if extraction failed
 */
export const extractConnectionDetails = async (
  request: PermissionRequest<PsqlPermissionSpec>,
  roleName: string,
  debug?: boolean,
  authn?: Authn,
  args?: yargs.ArgumentsCamelCase<PsqlCommandArgs>
): Promise<ConnectionDetails | null> => {
  try {
    const { permission, generated } = request;
    const perm = permission as Record<string, unknown>;
    const resource = permission.resource as Record<string, unknown>;

    // Detect provider FIRST before extracting provider-specific fields
    // Check multiple indicators: integration type, instance path, and resource metadata
    const integrationType =
      (perm.integrationType as string) || (resource.integrationType as string);
    const instancePath = (perm.instance as string) || "";
    const isGcp =
      integrationType === "cloudsql" ||
      integrationType === "cloud-sql" ||
      instancePath.toLowerCase().startsWith("cloud-sql/") ||
      instancePath.toLowerCase().includes("cloudsql") ||
      resource?.provider === "gcp" ||
      resource?.type === "gcp";

    if (debug) {
      print2(`Detected provider: ${isGcp ? "GCP CloudSQL" : "AWS RDS"}`);
      print2(`Integration type: ${integrationType || "not specified"}`);
      print2(`Instance path: ${instancePath || "not specified"}`);
    }

    // Extract common fields
    const region = (perm.region as string) || (resource?.region as string);
    const databaseName =
      (perm.databaseName as string) || (resource?.databaseName as string);
    const instanceName =
      (perm.instanceName as string) || (resource?.instanceName as string);

    // Extract provider-specific fields only if needed (AWS-specific fields)
    const accountId = isGcp
      ? undefined
      : (resource?.accountId as string) ||
        (resource?.account as string) ||
        (perm.parent as string);
    const idcId = isGcp ? undefined : (resource?.idcId as string);
    const idcRegion = isGcp
      ? undefined
      : (resource?.idcRegion as string) ||
        (resource?.idc_region as string) ||
        region;

    // Default port for PostgreSQL
    const port = (perm.port as number) || (resource?.port as number) || 5432;

    // Extract permission set name from generated resource (only for AWS)
    const gen = generated as Record<string, unknown>;
    const permissionSetName =
      ((gen?.resource as Record<string, unknown>)?.name as string) ||
      (gen?.permissionSet as string) ||
      roleName;

    if (debug && !isGcp) {
      print2(`Using permission set name: ${permissionSetName}`);
    }

    if (debug) {
      print2("=== Debug: Full response structure ===");
      print2("Full request object:");
      print2(JSON.stringify(request, null, 2));
      print2("\nFull permission object:");
      print2(JSON.stringify(permission, null, 2));
      print2("\nFull resource object:");
      print2(JSON.stringify(resource, null, 2));
      print2("\nFull generated object:");
      print2(JSON.stringify(generated, null, 2));
      print2("=== End debug ===");
    }

    // Route to provider-specific extraction
    if (isGcp) {
      return await extractGcpConnectionDetails(
        perm,
        resource,
        region,
        databaseName,
        instanceName,
        port,
        debug
      );
    } else {
      return await extractAwsConnectionDetails(
        perm,
        resource,
        region,
        databaseName,
        instanceName,
        accountId!,
        idcId!,
        idcRegion!,
        port,
        roleName,
        generated,
        debug,
        authn,
        args
      );
    }
  } catch (error) {
    print2(`Error extracting connection details: ${String(error)}`);
    if (debug) {
      print2(`Stack: ${error instanceof Error ? error.stack : String(error)}`);
    }
    return null;
  }
};
