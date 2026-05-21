/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authenticate } from "../drivers/auth";
import { print2 } from "../drivers/stdio";
import { traceSpan } from "../opentelemetry/otel-helpers";
import {
  generateTransferUrls,
  provisionTransferRequest,
} from "../plugins/file-transfer";
import * as fs from "fs/promises";
import yargs from "yargs";

export type FileTransferCommandArgs = {
  source: string;
  destination: string;
  reason?: string;
  debug?: boolean;
};

export const fileTransferCommand = (yargs: yargs.Argv) =>
  yargs.command<FileTransferCommandArgs>(
    "file-transfer <source> <destination>",
    "Transfer a local file to a remote instance via a temporary signed-URL bucket.",
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

      const authn = await authenticate(args);

      const target = await provisionTransferRequest(authn, args);

      const { putUrl, getUrl, deleteUrl } = await generateTransferUrls(
        authn,
        target,
        args.debug
      );

      if (args.debug) {
        print2(`PUT    (5m): ${putUrl}`);
        print2(`GET    (5m): ${getUrl}`);
        print2(`DELETE (1h): ${deleteUrl}`);
      }

      const buffer = await fs.readFile(args.source);
      const uploadResponse = await fetch(putUrl, {
        method: "PUT",
        body: buffer as unknown as BodyInit,
      });

      if (!uploadResponse.ok) {
        const body = await uploadResponse.text().catch(() => "");
        throw `Upload failed: ${uploadResponse.status} ${uploadResponse.statusText}${body ? `\n${body}` : ""}`;
      }

      print2("Uploaded.");
    },
    {
      command: "file-transfer",
    }
  );
};
