/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { WorkflowSpec } from "./types.js";

/**
 * Catalog of workflows the interactive TUI can run. Each entry mirrors
 * the corresponding yargs command's options. Specs are intentionally
 * thin — they describe what to ask the user; the executor module
 * dispatches to the real handler.
 *
 * Listing endpoints could power dynamic-select fields here (e.g. SSH
 * destinations from the SSH lister), but v0 uses text inputs across
 * the board for simplicity. The fields are designed so swapping a
 * `kind: "text"` to a `kind: "select"` later is non-breaking.
 */
export const WORKFLOWS: WorkflowSpec[] = [
  {
    id: "ssh",
    command: ["ssh"],
    description: "SSH into a virtual machine",
    searchTokens: ["shell", "remote", "ec2", "vm"],
    fields: [
      {
        kind: "text",
        key: "destination",
        label: "Destination",
        help: "Instance name or ID",
        required: true,
        positional: true,
        placeholder: "i-0abc… or instance-alias",
      },
      {
        kind: "text",
        key: "command",
        label: "Command",
        help: "Optional command to run instead of an interactive shell",
        positional: true,
      },
      {
        kind: "select",
        key: "provider",
        label: "Provider",
        help: "Cloud provider hosting the instance",
        options: [
          { label: "Auto-detect", value: "" },
          { label: "AWS", value: "aws" },
          { label: "Azure", value: "azure" },
          { label: "GCP", value: "gcloud" },
          { label: "Self-hosted", value: "self-hosted" },
        ],
      },
      {
        kind: "text",
        key: "parent",
        label: "Parent",
        help: "Parent resource (account / project / subscription)",
      },
      {
        kind: "toggle",
        key: "sudo",
        label: "Sudo",
        help: "Add user to sudoers file",
      },
      {
        kind: "text",
        key: "reason",
        label: "Reason",
        placeholder: "Why you need access",
      },
      {
        kind: "passthrough",
        key: "--",
        label: "Extra ssh args",
        help: "Args after `--` (e.g. -NR '*:8080:localhost:8088')",
      },
    ],
  },
  {
    id: "scp",
    command: ["scp"],
    description: "Copy files between local and remote hosts via SCP",
    searchTokens: ["copy", "transfer", "file"],
    fields: [
      {
        kind: "text",
        key: "source",
        label: "Source",
        help: "Format [host:]file",
        required: true,
        positional: true,
        placeholder: "local-file or host:/remote/path",
      },
      {
        kind: "text",
        key: "destination",
        label: "Destination",
        help: "Format [host:]file",
        required: true,
        positional: true,
        placeholder: "host:/remote/path or local-file",
      },
      {
        kind: "text",
        key: "account",
        label: "Account",
        help: "Parent account / project / subscription",
      },
      {
        kind: "select",
        key: "provider",
        label: "Provider",
        options: [
          { label: "Auto-detect", value: "" },
          { label: "AWS", value: "aws" },
          { label: "Azure", value: "azure" },
          { label: "GCP", value: "gcloud" },
          { label: "Self-hosted", value: "self-hosted" },
        ],
      },
      { kind: "toggle", key: "sudo", label: "Sudo" },
      { kind: "text", key: "reason", label: "Reason" },
      {
        kind: "passthrough",
        key: "--",
        label: "Extra scp args",
        help: "Args after `--`",
      },
    ],
  },
  {
    id: "rdp",
    command: ["rdp"],
    description: "Connect to a Windows VM via RDP",
    searchTokens: ["remote-desktop", "windows", "azure"],
    fields: [
      {
        kind: "text",
        key: "destination",
        label: "Destination",
        required: true,
        positional: true,
        placeholder: "my-windows-vm",
      },
      { kind: "text", key: "reason", label: "Reason" },
      {
        kind: "toggle",
        key: "configure",
        label: "Configure session before connecting",
      },
    ],
  },
  {
    id: "kubeconfig",
    command: ["kubeconfig"],
    description: "Configure kubectl for an EKS cluster",
    searchTokens: ["k8s", "kubernetes", "kubectl", "eks"],
    fields: [
      {
        kind: "text",
        key: "cluster",
        label: "Cluster",
        help: "ID of the cluster as configured in P0",
        required: true,
        placeholder: "my-cluster-id",
      },
      {
        kind: "text",
        key: "role",
        label: "Role",
        help: 'e.g. "ClusterRole/cluster-admin"',
        required: true,
        placeholder: "ClusterRole/cluster-admin",
      },
      {
        kind: "text",
        key: "resource",
        label: "Resource",
        help: 'e.g. "Pod / *" — omit for cluster-wide',
      },
      { kind: "text", key: "reason", label: "Reason" },
      {
        kind: "text",
        key: "duration",
        label: "Duration",
        placeholder: "1 hour",
      },
    ],
  },
  {
    id: "aws.rds.generate-db-auth-token",
    command: ["aws", "rds", "generate-db-auth-token"],
    description: "Generate an RDS IAM auth token",
    searchTokens: ["database", "db", "rds", "auth", "token"],
    fields: [
      {
        kind: "select",
        key: "arch",
        label: "Architecture",
        required: true,
        options: [
          { label: "MySQL / MariaDB", value: "mysql" },
          { label: "PostgreSQL", value: "postgres" },
        ],
      },
      {
        kind: "text",
        key: "role",
        label: "Role",
        help: "Database role to access",
        required: true,
      },
      {
        kind: "text",
        key: "instance",
        label: "Instance",
        help: "P0 instance identifier",
      },
      { kind: "text", key: "database", label: "Database" },
      { kind: "text", key: "account", label: "AWS account ID or alias" },
      { kind: "text", key: "reason", label: "Reason" },
    ],
  },
  {
    id: "aws.role.assume",
    command: ["aws", "role", "assume"],
    description: "Assume an AWS IAM role",
    searchTokens: ["iam", "credentials", "saml"],
    fields: [
      {
        kind: "text",
        key: "role",
        label: "Role",
        help: "IAM role name to assume",
        required: true,
        positional: true,
      },
      { kind: "text", key: "account", label: "AWS account ID or alias" },
      { kind: "text", key: "reason", label: "Reason" },
    ],
  },
  {
    id: "aws.permission-set.assume",
    command: ["aws", "permission-set", "assume"],
    description: "Assume an AWS IAM Identity Center permission set",
    searchTokens: ["idc", "sso", "permission-set", "credentials"],
    fields: [
      {
        kind: "text",
        key: "permission-set",
        label: "Permission set",
        required: true,
        positional: true,
      },
      { kind: "text", key: "account", label: "AWS account ID or alias" },
      { kind: "text", key: "reason", label: "Reason" },
    ],
  },
];

/** Looks up a workflow spec by id. */
export const findWorkflow = (id: string): WorkflowSpec | undefined =>
  WORKFLOWS.find((w) => w.id === id);
