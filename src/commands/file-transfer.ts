/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { retryWithSleep } from "../common/retry";
import { authenticate } from "../drivers/auth";
import { print2 } from "../drivers/stdio";
import { traceSpan } from "../opentelemetry/otel-helpers";
import {
  createTransferClient,
  generateTransferUrls,
  provisionTransferRequest,
} from "../plugins/file-transfer";
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

      // target.prefix is the backend-granted prefix (ends in `/`); append the
      // local file's basename so the S3 object preserves the original filename.
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

      // Sign the download/cleanup URLs only now that the file is uploaded — the
      // GET window is finite, so we don't want it ticking during the upload.
      const { getUrl, deleteUrl, expirySeconds } = await generateTransferUrls(
        authn,
        s3,
        { bucket: target.bucket, key: uploadKey, awsSpec: target.awsSpec },
        args.debug
      );

      // TODO: remove logging when we remove the launchdarkly file-transfer flag
      if (args.debug) {
        print2(`GET    (${renderDurationSec(expirySeconds.get)}): ${getUrl}`);
        print2(
          `DELETE (${renderDurationSec(expirySeconds.delete)}): ${deleteUrl}`
        );
      }
    },
    {
      command: "file-transfer",
    }
  );
};
