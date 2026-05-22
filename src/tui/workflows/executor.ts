/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  SuppressedExit,
  setSuppressExit,
} from "../../opentelemetry/otel-helpers.js";
import { parsePassthrough } from "./preview.js";
import { WorkflowValues } from "./types.js";

/**
 * Result of running a workflow from the TUI. `error` is set when the
 * handler threw; the TUI surfaces it on re-mount. SSH/SCP/RDP handlers
 * call `exitProcess` on completion — the TUI loop sets
 * {@link setSuppressExit} so that becomes a controlled throw of
 * {@link SuppressedExit} rather than killing the process.
 */
export type WorkflowResult = {
  ok: boolean;
  message?: string;
};

const toString = (v: WorkflowValues[string]): string | undefined =>
  typeof v === "string" && v.length > 0 ? v : undefined;

const toBool = (v: WorkflowValues[string]): boolean | undefined =>
  typeof v === "boolean" ? v : undefined;

/**
 * Runs the given workflow with the values collected from the TUI form.
 * The TUI must have unmounted before calling this so the handler can
 * own the terminal (print status, spawn SSH, etc.).
 *
 * SSH/SCP/RDP handlers call `exitProcess` on their happy path; this
 * function wraps each call with `setSuppressExit(true)` so those
 * "exits" become catchable throws of the `SuppressedExit` sentinel,
 * letting the TUI loop re-mount.
 */
export const runWorkflow = async (
  workflowId: string,
  values: WorkflowValues,
  debug?: boolean
): Promise<WorkflowResult> => {
  const argv = buildArgv(workflowId, values, debug);
  if (!argv) {
    return { ok: false, message: `Missing required input for ${workflowId}` };
  }

  const previousSuppress = setSuppressExit(true);
  try {
    const { runCommands } = await import("../../commands/index.js");
    await runCommands(argv);
    return { ok: true };
  } catch (err) {
    if (err === SuppressedExit) {
      // Handler called exitProcess on its happy path (SSH/SCP/RDP).
      return { ok: true };
    }
    return { ok: false, message: errorMessage(err) };
  } finally {
    setSuppressExit(previousSuppress);
  }
};

/**
 * Translates the workflow's form values back into a `p0 ...` argv
 * array — exactly the form yargs sees in non-interactive mode. Returns
 * undefined when required fields are missing.
 */
const buildArgv = (
  workflowId: string,
  values: WorkflowValues,
  debug?: boolean
): string[] | undefined => {
  switch (workflowId) {
    case "ssh":
      return buildSshArgv(values, debug);
    case "scp":
      return buildScpArgv(values, debug);
    case "rdp":
      return buildRdpArgv(values, debug);
    case "kubeconfig":
      return buildKubeconfigArgv(values, debug);
    case "aws.rds.generate-db-auth-token":
      return buildAwsRdsArgv(values, debug);
    case "aws.role.assume":
      return buildAwsRoleAssumeArgv(values, debug);
    case "aws.permission-set.assume":
      return buildAwsPermissionSetAssumeArgv(values, debug);
    default:
      return undefined;
  }
};

const buildSshArgv = (
  values: WorkflowValues,
  debug?: boolean
): string[] | undefined => {
  const destination = toString(values["destination"]);
  if (!destination) return undefined;
  const argv: string[] = ["ssh", destination];
  const cmd = toString(values["command"]);
  if (cmd) argv.push(cmd);
  const provider = toString(values["provider"]);
  if (provider) argv.push("--provider", provider);
  const parent = toString(values["parent"]);
  if (parent) argv.push("--parent", parent);
  if (toBool(values["sudo"])) argv.push("--sudo");
  const reason = toString(values["reason"]);
  if (reason) argv.push("--reason", reason);
  if (debug) argv.push("--debug");
  const passthrough = parsePassthrough(
    typeof values["--"] === "string" ? values["--"] : undefined
  );
  if (passthrough.length > 0) argv.push("--", ...passthrough);
  return argv;
};

const buildScpArgv = (
  values: WorkflowValues,
  debug?: boolean
): string[] | undefined => {
  const source = toString(values["source"]);
  const destination = toString(values["destination"]);
  if (!source || !destination) return undefined;
  const argv: string[] = ["scp", source, destination];
  const provider = toString(values["provider"]);
  if (provider) argv.push("--provider", provider);
  const account = toString(values["account"]);
  if (account) argv.push("--account", account);
  if (toBool(values["sudo"])) argv.push("--sudo");
  const reason = toString(values["reason"]);
  if (reason) argv.push("--reason", reason);
  if (debug) argv.push("--debug");
  const passthrough = parsePassthrough(
    typeof values["--"] === "string" ? values["--"] : undefined
  );
  if (passthrough.length > 0) argv.push("--", ...passthrough);
  return argv;
};

const buildRdpArgv = (
  values: WorkflowValues,
  debug?: boolean
): string[] | undefined => {
  const destination = toString(values["destination"]);
  if (!destination) return undefined;
  const argv: string[] = ["rdp", destination];
  const reason = toString(values["reason"]);
  if (reason) argv.push("--reason", reason);
  if (toBool(values["configure"])) argv.push("--configure");
  if (debug) argv.push("--debug");
  return argv;
};

const buildKubeconfigArgv = (
  values: WorkflowValues,
  debug?: boolean
): string[] | undefined => {
  const cluster = toString(values["cluster"]);
  const role = toString(values["role"]);
  if (!cluster || !role) return undefined;
  const argv: string[] = ["kubeconfig", "--cluster", cluster, "--role", role];
  const resource = toString(values["resource"]);
  if (resource) argv.push("--resource", resource);
  const reason = toString(values["reason"]);
  if (reason) argv.push("--reason", reason);
  const duration = toString(values["duration"]);
  if (duration) argv.push("--duration", duration);
  if (debug) argv.push("--debug");
  return argv;
};

const buildAwsRdsArgv = (
  values: WorkflowValues,
  debug?: boolean
): string[] | undefined => {
  const arch = toString(values["arch"]);
  const role = toString(values["role"]);
  if (!arch || !role) return undefined;
  const argv: string[] = ["aws"];
  const account = toString(values["account"]);
  if (account) argv.push("--account", account);
  const reason = toString(values["reason"]);
  if (reason) argv.push("--reason", reason);
  argv.push("rds", "generate-db-auth-token", "--arch", arch, "--role", role);
  const instance = toString(values["instance"]);
  if (instance) argv.push("--instance", instance);
  const database = toString(values["database"]);
  if (database) argv.push("--database", database);
  if (debug) argv.push("--debug");
  return argv;
};

const buildAwsRoleAssumeArgv = (
  values: WorkflowValues,
  debug?: boolean
): string[] | undefined => {
  const role = toString(values["role"]);
  if (!role) return undefined;
  const argv: string[] = ["aws"];
  const account = toString(values["account"]);
  if (account) argv.push("--account", account);
  const reason = toString(values["reason"]);
  if (reason) argv.push("--reason", reason);
  argv.push("role", "assume", role);
  if (debug) argv.push("--debug");
  return argv;
};

const buildAwsPermissionSetAssumeArgv = (
  values: WorkflowValues,
  debug?: boolean
): string[] | undefined => {
  const ps = toString(values["permission-set"]);
  if (!ps) return undefined;
  const argv: string[] = ["aws"];
  const account = toString(values["account"]);
  if (account) argv.push("--account", account);
  const reason = toString(values["reason"]);
  if (reason) argv.push("--reason", reason);
  argv.push("permission-set", "assume", ps);
  if (debug) argv.push("--debug");
  return argv;
};

const errorMessage = (err: unknown): string => {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
};
