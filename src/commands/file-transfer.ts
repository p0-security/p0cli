/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { retryWithSleep } from "../common/retry";
import { authenticate } from "../drivers/auth";
import { print2 } from "../drivers/stdio";
import { exitProcess, traceSpan } from "../opentelemetry/otel-helpers";
import {
  createTransferClient,
  generateSignedUrl,
  provisionTransferRequest,
} from "../plugins/file-transfer";
import { sshOrScp } from "../plugins/ssh";
import { prepareRequest } from "./shared/ssh";
import { DeleteObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { Upload } from "@aws-sdk/lib-storage";
import { createReadStream, statSync } from "fs";
import { basename } from "node:path";
import yargs from "yargs";

export type FileTransferCommandArgs = {
  source: string;
  destination: string;
  reason?: string;
  debug?: boolean;
};

const renderDurationSec = (s: number) =>
  s >= 3600 ? `${Math.round(s / 3600)}h` : `${Math.round(s / 60)}m`;

// Standard POSIX shell exit code for "command not found".
const COMMAND_NOT_FOUND_EXIT_CODE = 127;
const SUCCESS_EXIT_CODE = 0;

/**
 * Best-effort cleanup of the uploaded S3 object. The CLI already holds an
 * authenticated S3 client, so it deletes directly and the client also
 * auto-refreshes credentials.
 *
 * This must never fail an otherwise-successful transfer: the object still
 * expires via the bucket's lifecycle policy, so a failed delete is harmless.
 * The result therefore defaults to success — errors are only surfaced under
 * --debug.
 */
const deleteUploadedObject = async (
  s3: S3Client,
  bucket: string,
  key: string,
  debug?: boolean
) => {
  try {
    await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
    if (debug) {
      print2(`Deleted s3://${bucket}/${key} from the bucket.`);
    }
  } catch (err) {
    print2(
      `Warning: could not delete s3://${bucket}/${key}. The file transfer succeeded, 
      so this is safe to ignore. You may delete this object manually, or it will be 
      removed automatically by the file-transfer bucket's lifecycle expiration 
      rule.`
    );
    // The raw error is debugging detail, not outcome info.
    if (debug) {
      const message = err instanceof Error ? err.message : String(err);
      print2(`Delete error: ${message}`);
    }
  }
};

export const fileTransferCommand = (yargs: yargs.Argv) =>
  yargs.command<FileTransferCommandArgs>(
    "file-transfer <source> <destination>",
    "Transfer a local file to a remote instance via a temporary S3 bucket.",
    (yargs) =>
      yargs
        .positional("source", {
          type: "string",
          demandOption: true,
          description: "Local file path",
        })
        .positional("destination", {
          type: "string",
          demandOption: true,
          description: "Instance ID of the transfer destination",
        })
        .option("reason", {
          type: "string",
          describe: "Reason access is needed",
        })
        .option("debug", {
          type: "boolean",
          describe: "Print debug information, including signed URLs.",
        }),
    fileTransferAction
  );

const fileTransferAction = async (
  args: yargs.ArgumentsCamelCase<FileTransferCommandArgs>
) => {
  await traceSpan(
    "file-transfer.command",
    async (span) => {
      span.setAttribute("source", args.source);
      span.setAttribute("destination", args.destination);

      // Fail before requesting backend approval if the source can't be uploaded —
      // a missing path or directory would otherwise only surface mid-upload, after
      // the user has already waited on the approval flow.
      let sourceStats;
      try {
        sourceStats = statSync(args.source);
      } catch {
        throw `Source file not found: ${args.source}`;
      }
      if (!sourceStats.isFile()) {
        throw `Source path is not a regular file: ${args.source}`;
      }

      const authn = await authenticate(args);

      print2("Requesting file-transfer access...");
      const target = await provisionTransferRequest(authn, args);
      print2(`Access approved for s3://${target.bucket}/${target.prefix}`);

      // append original basename so the S3 object preserves the original filename.
      const uploadKey = `${target.prefix}${basename(args.source)}`;

      print2("Preparing upload credentials...");
      const s3 = createTransferClient(authn, target, args.debug);

      print2(`Uploading ${args.source}...`);

      // The backend grants the AWS role permission to write to our prefix, but
      // IAM has eventual consistency — the policy can take several seconds to
      // propagate before S3 honors it. Retry AccessDenied so the first
      // invocation just works instead of failing the user.
      try {
        await retryWithSleep(
          async () => {
            const upload = new Upload({
              client: s3,
              params: {
                Bucket: target.bucket,
                Key: uploadKey,
                Body: createReadStream(args.source),
              },
            });
            upload.on("httpUploadProgress", (progress) => {
              const loaded = progress.loaded ?? 0;
              const total = progress.total ?? 0;
              const mb = (loaded / 1024 / 1024).toFixed(1);
              const pct = total
                ? ` (${Math.round((loaded / total) * 100)}%)`
                : "";
              print2(`  uploaded ${mb} MB${pct}`);
            });
            await upload.done();
          },
          {
            retries: 20,
            delayMs: 2_000,
            maxDelayMs: 10_000,
            multiplier: 1.5,
            jitterFactor: 0.3,
            // AWS SDK v3 sets `name` to the AWS error code. Matching the typed
            // field avoids breaking if a future SDK reworks the message text.
            shouldRetry: (err) =>
              err instanceof Error && err.name === "AccessDenied",
            debug: args.debug,
          }
        );
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        throw `Upload failed: ${message}`;
      }

      print2("Uploaded.");

      // TODO we need to remove this second request. it should be included in file transfer delegation. Will be removed in future ticket
      print2(`Requesting download access on ${args.destination}...`);

      // Drop `source` (local file path) before passing to SSH plumbing —
      // `createCommand` uses `"source" in args` to branch between scp and ssh path, and we want the ssh branch here.
      const { source: _source, ...sshBaseArgs } = args;
      const sshCmdArgs = {
        ...sshBaseArgs,
        arguments: [],
        sshOptions: [],
      };

      const { request, requestId, privateKey, sshProvider, sshHostKeys } =
        await prepareRequest(authn, sshCmdArgs, args.destination);

      // Sign GET URL now so the 5-min TTL starts after approval clears,
      // not before — otherwise long approval waits could expire the URL.
      const { signedUrl: getUrl, expirySeconds: getExpirySeconds } =
        await generateSignedUrl(
          authn,
          s3,
          { bucket: target.bucket, key: uploadKey, awsSpec: target.awsSpec },
          "get",
          args.debug
        );
      if (args.debug) {
        print2(`GET    (${renderDurationSec(getExpirySeconds)}): ${getUrl}`);
      }

      const remotePath = `/home/${request.linuxUserName}/${basename(args.source)}`;
      print2(
        `Downloading to ${request.linuxUserName}@${args.destination}:${remotePath}...`
      );

      // TODO decide final downloader to use and maybe add fallback downloaders if not present. Using curl for now — universally present on mainstream EC2 AMIs (Amazon Linux, Ubuntu, RHEL, etc.).
      const downloadCmdArgs = {
        ...sshCmdArgs,
        command: "curl",
        arguments: ["-sSfL", getUrl, "-o", remotePath],
      };

      const exitCode = await sshOrScp({
        authn,
        request,
        requestId,
        cmdArgs: downloadCmdArgs,
        privateKey,
        sshProvider,
        sshHostKeys,
      });

      // curl is the only downloader today; revisit this branch if we add fallbacks
      if (exitCode === COMMAND_NOT_FOUND_EXIT_CODE) {
        throw `curl not found on ${args.destination}. The file is in S3 — install curl on the destination instance and re-run file-transfer command`;
      }

      if (exitCode === SUCCESS_EXIT_CODE) {
        // Success path: the file is on the instance, so clean it from the bucket.
        print2(`Downloaded to ${remotePath}.`);
        await deleteUploadedObject(s3, target.bucket, uploadKey, args.debug);
      } else if (exitCode === null) {
        throw `Remote download was interrupted before completing ... re-run the file-transfer command`;
      } else {
        throw `Remote download exited with code ${exitCode}`;
      }

      // Force exit to prevent hanging due to orphaned child processes (e.g.,
      // session-manager-plugin) holding open file descriptors. See:
      // https://github.com/aws/amazon-ssm-agent/issues/173
      if (process.env.NODE_ENV !== "unit") {
        exitProcess(0);
      }
    },
    {
      command: "file-transfer",
    }
  );
};
