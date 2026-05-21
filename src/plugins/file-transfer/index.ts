/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { FileTransferCommandArgs } from "../../commands/file-transfer";
import { request } from "../../commands/shared/request";
import { Authn } from "../../types/identity";
import { PermissionRequest } from "../../types/request";
import { awsCloudAuth } from "../aws/auth";
import {
  FileTransferPermissionSpec,
  TransferTarget,
  TransferUrls,
} from "./types";
import {
  DeleteObjectCommand,
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { pick } from "lodash";
import yargs from "yargs";

const PUT_EXPIRES_SECONDS = 5 * 60;
const GET_EXPIRES_SECONDS = 5 * 60;
const DELETE_EXPIRES_SECONDS = 60 * 60;

export const provisionTransferRequest = async (
  authn: Authn,
  args: yargs.ArgumentsCamelCase<FileTransferCommandArgs>
): Promise<TransferTarget> => {
  const response = await request("request")<
    PermissionRequest<FileTransferPermissionSpec>
  >(
    {
      ...pick(args, "$0", "_"),
      arguments: [
        "file-transfer",
        "session",
        args.destination,
        ...(args.reason ? ["--reason", args.reason] : []),
      ],
      wait: true,
    },
    authn,
    { message: "approval-required" }
  );

  if (!response) {
    throw "Did not receive a response from server";
  }

  const awsSpec = response.request.delegation.aws;
  if (!awsSpec) {
    throw "Backend granted file-transfer access, but did not provide AWS delegation";
  }

  const { bucketName, objectKey, region } =
    response.request.permission.resource;

  return {
    bucket: bucketName,
    key: objectKey,
    region,
    awsSpec,
  };
};

export const generateTransferUrls = async (
  authn: Authn,
  target: TransferTarget,
  debug?: boolean
): Promise<TransferUrls> => {
  const credentials = await awsCloudAuth(authn, target.awsSpec, debug);

  const sdkCredentials = {
    accessKeyId: credentials.AWS_ACCESS_KEY_ID,
    secretAccessKey: credentials.AWS_SECRET_ACCESS_KEY,
    sessionToken: credentials.AWS_SESSION_TOKEN,
  };

  // The bucket may not be in the same region as the destination instance.
  // S3 returns the `x-amz-bucket-region` header on any request to an existing
  // bucket — including unauthenticated 403/301 responses — so we can discover
  // the region without needing s3:ListBucket on the role.
  const probeResponse = await fetch(
    `https://${target.bucket}.s3.us-east-1.amazonaws.com/`,
    { method: "HEAD" }
  );
  const bucketRegion =
    probeResponse.headers.get("x-amz-bucket-region") ?? target.region;

  const s3 = new S3Client({
    region: bucketRegion,
    credentials: sdkCredentials,
  });

  const objectArgs = { Bucket: target.bucket, Key: target.key };
  const [putUrl, getUrl, deleteUrl] = await Promise.all([
    getSignedUrl(s3, new PutObjectCommand(objectArgs), {
      expiresIn: PUT_EXPIRES_SECONDS,
    }),
    getSignedUrl(s3, new GetObjectCommand(objectArgs), {
      expiresIn: GET_EXPIRES_SECONDS,
    }),
    getSignedUrl(s3, new DeleteObjectCommand(objectArgs), {
      expiresIn: DELETE_EXPIRES_SECONDS,
    }),
  ]);

  return { putUrl, getUrl, deleteUrl };
};
