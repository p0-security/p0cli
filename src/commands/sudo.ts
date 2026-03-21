/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authenticate } from "../drivers/auth";
import { print2 } from "../drivers/stdio";
import { exitProcess, traceSpan } from "../opentelemetry/otel-helpers";
import { request } from "./shared/request";
import { spawn } from "child_process";
import { hostname } from "os";
import yargs from "yargs";

const PROPAGATION_RETRY_DELAY_MS = 2_000;
const PROPAGATION_TIMEOUT_MS = 20_000;

type SudoCommandArgs = {
  u: string;
  command?: string;
  arguments: string[];
  reason?: string;
  debug?: boolean;
};

export const sudoCommand = (yargs: yargs.Argv) =>
  yargs.command<SudoCommandArgs>(
    "sudo [command [arguments..]]",
    "Run a command as another user with P0-managed access",
    (yargs) =>
      yargs
        .option("u", {
          alias: "user",
          type: "string",
          demandOption: true,
          describe: "User to run the command as",
        })
        .positional("command", {
          type: "string",
          describe: "Command to run",
        })
        .positional("arguments", {
          describe: "Command arguments",
          array: true,
          string: true,
          default: [] as string[],
        })
        .option("reason", {
          describe: "Reason access is needed",
          type: "string",
        })
        .option("debug", {
          type: "boolean",
          describe: "Print debug information.",
        }),
    sudoAction
  );

/** Polls `sudo -n -u <user> -v` until the sudoers entry propagates on this host,
 *  or until the deadline is exceeded. Returns true if access propagated.
 *
 *  The -n flag makes sudo non-interactive: it exits with a non-zero code
 *  instead of prompting for a password, so this never blocks on stdin. */
const waitForSudoAccessPropagation = async (
  user: string,
  deadline: number
): Promise<boolean> => {
  for (;;) {
    const exitCode = await new Promise<number>((resolve) => {
      const probe = spawn("sudo", ["-n", "-u", user, "-v"], {
        stdio: "ignore",
      });
      probe.on("exit", (code) => resolve(code ?? 1));
      probe.on("error", () => resolve(1));
    });

    if (exitCode === 0) return true;

    if (Date.now() >= deadline) return false;

    print2("Waiting for sudo access to propagate...");
    await new Promise((r) => setTimeout(r, PROPAGATION_RETRY_DELAY_MS));
  }
};

const sudoAction = async (args: yargs.ArgumentsCamelCase<SudoCommandArgs>) => {
  await traceSpan(
    "sudo.command",
    async (span) => {
      span.setAttribute("user", args.u);

      const authn = await authenticate(args);
      const host = hostname();

      // Request P0 access: p0 request self-hosted user <hostname> <username>
      const response = await request("request")(
        {
          ...args,
          arguments: [
            "self-hosted",
            "user",
            host,
            args.u,
            ...(args.reason ? ["--reason", args.reason] : []),
          ],
          wait: true,
        },
        authn,
        { message: "approval-required" }
      );

      if (!response) {
        exitProcess(1);
        return;
      }

      if (!args.command) {
        print2("No command specified");
        exitProcess(1);
        return;
      }

      const deadline = Date.now() + PROPAGATION_TIMEOUT_MS;
      const propagated = await waitForSudoAccessPropagation(args.u, deadline);
      if (!propagated) {
        print2("Timed out waiting for sudo access to propagate");
        exitProcess(1);
        return;
      }

      // Access is confirmed — run the real command
      const exitCode = await new Promise<number>((resolve) => {
        const child = spawn(
          "sudo",
          ["-u", args.u, args.command!, ...args.arguments],
          { stdio: "inherit" }
        );
        child.on("exit", (code) => resolve(code ?? 1));
        child.on("error", (err) => {
          print2(`Failed to run sudo: ${err.message}`);
          resolve(1);
        });
      });

      exitProcess(exitCode);
    },
    { command: "sudo" }
  );
};
