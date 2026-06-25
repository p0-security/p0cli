/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { FileTransferCommandArgs } from "../../commands/file-transfer";
import { decodeProvisionStatus } from "../../commands/shared";
import { request } from "../../commands/shared/request";
import { newSshRequestErrorHandler } from "../../commands/shared/ssh";
import { getDelegate } from "../../types/delegation";
import { Authn } from "../../types/identity";
import { PermissionRequest } from "../../types/request";
import { awsCloudAuth } from "../aws/auth";
import { AwsResourcePermissionSpec } from "../aws/types";
import { FileTransferPermissionSpec } from "./types";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { pick } from "lodash";
import { sys } from "typescript";
import yargs from "yargs";

export const MAX_SECONDS_TO_EXPIRE_GET_URL = 5 * 60;
const MIN_URL_EXPIRY_THRESHOLD_SECONDS = 60;

export const provisionTransferRequest = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<FileTransferCommandArgs>,
  publicKey: string
) => {
  // Always prints the error, but adds a hint if we think a username was included in the destination instance name by mistake.
  const requestErrorHandler = newSshRequestErrorHandler(args.destination);

  const response = await request("request")<
    PermissionRequest<FileTransferPermissionSpec>
  >(
    {
      ...pick(args, "$0", "_"),
      arguments: [
        "file-transfer",
        "session",
        args.destination,
        "--public-key",
        publicKey,
        ...(args.reason ? ["--reason", args.reason] : []),
      ],
      wait: true,
    },
    authn,
    { message: "approval-required" }
  ).catch(requestErrorHandler);

  if (!response) {
    throw "Did not receive a response from server";
  }

  const result = await decodeProvisionStatus<FileTransferPermissionSpec>(
    response.request
  );
  if (!result) sys.exit(1);

  const { id: requestId } = response;
  const { status, principal } = response.request;

  const awsSpec = getDelegate(response.request.delegation, "aws");
  if (!awsSpec) {
    throw "Backend granted file-transfer access, but there was an error getting AWS access details";
  }

  const sshSpec = getDelegate(response.request.delegation, "ssh");

  if (!sshSpec) {
    throw "Backend granted file-transfer access, but there was an error getting SSH access details";
  }

  const delegatedSshRequest = {
    ...sshSpec,
    status,
    principal,
  };

  const { bucketName, bucketRegion, objectPrefix } =
    response.request.permission.resource;

  return {
    target: {
      bucket: bucketName,
      prefix: objectPrefix,
      region: bucketRegion,
      awsSpec,
      sshSpec,
    },
    // needed for further delegate ssh request processing within file-transfer command
    delegatedSshRequest,
    requestId,
  };
};

/**
 * Builds an S3 client whose credentials refresh automatically. A large upload
 * can run longer than the temporary credentials live; passing a provider
 * function (that returns `expiration`) lets the SDK re-fetch fresh credentials
 * mid-upload instead of failing the in-flight parts with ExpiredToken.
 */
export const createTransferClient = (
  authn: Authn,
  target: { region: string; awsSpec: AwsResourcePermissionSpec },
  debug?: boolean
): S3Client =>
  new S3Client({
    region: target.region,
    credentials: async () => {
      const credentials = await awsCloudAuth(authn, target.awsSpec, debug);
      return {
        accessKeyId: credentials.AWS_ACCESS_KEY_ID,
        secretAccessKey: credentials.AWS_SECRET_ACCESS_KEY,
        sessionToken: credentials.AWS_SESSION_TOKEN,
        // Providing `expiration` is what tells the SDK to treat these creds as
        // temporary. The SDK caches them and re-invokes this provider once they
        // expire (or are within its skew window).
        ...(credentials.expiresAt !== undefined
          ? { expiration: new Date(credentials.expiresAt) }
          : {}),
      };
    },
  });

/**
 * Signs the GET (download) URL. Call this AFTER the upload completes: the GET
 * window is finite, and signing before a large upload would burn that window
 * while the file is still uploading.
 *
 * The expiry is capped to the credentials' remaining lifetime so the URL can
 * never outlive the credentials that signed it.
 */
export const generateSignedUrl = async (
  authn: Authn,
  s3: S3Client,
  target: { bucket: string; key: string; awsSpec: AwsResourcePermissionSpec },
  debug?: boolean
): Promise<{
  signedUrl: string;
  expirySeconds: number;
}> => {
  const { expiresAt } = await awsCloudAuth(authn, target.awsSpec, debug);
  const remaining =
    expiresAt !== undefined
      ? Math.floor((expiresAt - Date.now()) / 1000)
      : Infinity;
  if (remaining < MIN_URL_EXPIRY_THRESHOLD_SECONDS) {
    throw new Error(
      `AWS credentials expire in ${remaining}s — too soon to sign usable URLs. ` +
        `Check your system clock or re-run the request.`
    );
  }

  const secondsToExpireUrl = Math.min(MAX_SECONDS_TO_EXPIRE_GET_URL, remaining);

  const signedUrl = await getSignedUrl(
    s3,
    new GetObjectCommand({ Bucket: target.bucket, Key: target.key }),
    { expiresIn: secondsToExpireUrl }
  );

  return {
    signedUrl,
    // Report the ACTUAL (capped) seconds so debug output is honest.
    expirySeconds: secondsToExpireUrl,
  };
};
