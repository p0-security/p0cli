/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authFetch, tenantUrl } from "../../drivers/api";
import { authenticate } from "../../drivers/auth";
import { postfixPath } from "../../drivers/auth/path";
import { debug, print2 } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import { assertNever, getOperatingSystem } from "../../util";
import assert from "node:assert";
import { exec, spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import yargs from "yargs";

type ListMcpServersResp = {
  servers: { id: string; url: string }[];
};

type CreateMcpClientReq = {
  hostname: string;
  platform: string;
  redirectUri: string;
  version: string;
};

type CreateMcpClientResp = {
  client: { id: string; redirectUri: string; secret: string };
  server: { id: string; url: string };
};

type GetMcpServerResp = {
  server: {
    id: string;
    url: string;
  };
};

type ListMcpServerArgs = yargs.ArgumentsCamelCase<{
  debug?: boolean;
}>;

type AddMcpServerArgs = yargs.ArgumentsCamelCase<{
  debug?: boolean;
  callbackPort: number | undefined;
  scope: string | undefined;
  server: string;
}>;

const CLIENT_PATH = postfixPath("claude/mcp-client.json");

// In dev use cases the default port (=8080) is likely to be consumed by another listening service.
// Avoid by defaulting to a random port valid for both Windows and *nix architectures.
const REDIRECT_PORT = 52566;

export const mcpCommand = (yargs: yargs.Argv<{ debug?: boolean }>) =>
  yargs
    .command(
      "add <server>",
      "Add an MCP server",
      (y) =>
        y
          .positional("server", {
            type: "string",
            describe: "MCP server key",
            demand: true,
          })
          .option("callbackPort", {
            describe: "Authentication callback port",
            type: "number",
            default: REDIRECT_PORT,
          })
          .option("scope", {
            alias: "s",
            describe:
              'Configuration scope (local, user, or project) (default: "local")',
            type: "string",
            choices: ["local", "user", "project"],
          }),
      async (argv) => {
        assert(argv.server);
        await handleAddMcpServer({ ...argv, server: argv.server });
      }
    )
    .command(
      "list",
      "List available MCP servers",
      (y) => y,
      async (argv) => {
        await handleListMcpServers(argv);
      }
    );

const handleListMcpServers = async (argv: ListMcpServerArgs) => {
  const authn = await authenticate();

  const result = await authFetch<ListMcpServersResp>(authn, {
    url: `${tenantUrl(authn.identity.org.slug)}/mcp/servers`,
    method: "GET",
    debug: argv.debug,
  });
  print2(result);
};

const handleAddMcpServer = async (argv: AddMcpServerArgs) => {
  const authn = await authenticate();

  if (!argv.server) {
    throw "'server' is required";
  }

  const client = await ensureClient(authn, argv);
  const server = await getServer(authn, argv);

  await provisionServer(argv, client, server);
};

const getHostname = async () => {
  const os = getOperatingSystem();
  switch (os) {
    case "mac":
      return (await promisify(exec)("scutil --get LocalHostName")).stdout;
    case "linux":
    case "win":
      return (await promisify(exec)("hostname")).stdout;
    case "unknown":
      throw `Unsupported operating system: ${os}`;
    default:
      throw assertNever(os);
  }
};

const createClient = async (authn: Authn, argv: AddMcpServerArgs) => {
  const version = (await promisify(exec)("claude --version")).stdout;
  const hostname = await getHostname();

  const clientData = await authFetch<CreateMcpClientResp>(authn, {
    url: `${tenantUrl(authn.identity.org.slug)}/mcp/clients`,
    method: "POST",
    body: JSON.stringify({
      hostname,
      platform: "claude-code",
      version,
      redirectUri: `http://localhost:${argv.callbackPort ?? REDIRECT_PORT}`,
    } satisfies CreateMcpClientReq),
    debug: argv.debug,
  });

  await fs.mkdir(path.dirname(CLIENT_PATH), { recursive: true });
  await fs.writeFile(CLIENT_PATH, JSON.stringify(clientData, null, 2), {
    mode: "400",
  });

  return clientData;
};

const ensureClient = async (authn: Authn, argv: AddMcpServerArgs) => {
  try {
    const cachedClientData = await fs.readFile(CLIENT_PATH, {
      encoding: "utf-8",
    });

    if (cachedClientData) {
      const client = JSON.parse(cachedClientData) as CreateMcpClientResp;
      debug(
        argv,
        "Using cached client at",
        CLIENT_PATH,
        "(remove this file to use a new MCP client)"
      );
      return client;
    }
  } catch (error: unknown) {
    debug(argv, `Could not read client data file: String(error)`);
  }

  return await createClient(authn, argv);
};

const getServer = async (authn: Authn, argv: AddMcpServerArgs) =>
  await authFetch<GetMcpServerResp>(authn, {
    url: `${tenantUrl(authn.identity.org.slug)}/mcp/servers/${encodeURIComponent(argv.server)}`,
    method: "GET",
  });

const getClaudeFile = async () => {
  const os = getOperatingSystem();
  switch (os) {
    case "linux":
    case "mac":
      return (await promisify(exec)("which claude")).stdout.trim();
    case "win": {
      const lines = (await promisify(exec)("where.exe claude")).stdout
        .split("\r\n")
        .map((l) => l.trim())
        .filter(Boolean);
      return lines.find((l) => l.endsWith(".cmd")) ?? lines[0] ?? "";
    }
    case "unknown":
      throw `Unsupported operating system: ${os}`;
    default:
      throw assertNever(os);
  }
};

const provisionServer = async (
  argv: AddMcpServerArgs,
  { client }: CreateMcpClientResp,
  { server }: GetMcpServerResp
) => {
  const claudeFile = await getClaudeFile();
  assert(client.secret, "No client secret");
  debug(argv, "Server", server);
  // Claude Code's `mcp add-json` doesn't accept oauth fields in its JSON
  // schema (verified against claude 2.1.141). Use `claude mcp add` with
  // explicit OAuth flags instead — the resulting `~/.claude.json` shape
  // is the same `{ type: "http", url, oauth: { clientId, callbackPort } }`
  // that the add-json form would have produced, but assembled by claude
  // from the flags rather than parsed from the JSON.
  //
  // The client secret is delivered via the MCP_CLIENT_SECRET env var (+
  // the `--client-secret` flag), so it never lands on disk.
  const callbackPort = Number(client.redirectUri.split(":").at(-1)!);
  const args = [
    "mcp",
    "add",
    "--transport",
    "http",
    "--client-id",
    client.id,
    "--callback-port",
    String(callbackPort),
    "--client-secret",
    ...(argv.scope ? ["--scope", argv.scope] : []),
    server.id,
    server.url,
  ];
  debug(argv, "Client secret", client.secret);
  debug(argv, ["claude", ...args].join(" "));
  // Spread process.env so the spawned `claude` inherits PATH / HOME /
  // NODE_OPTIONS / etc. (`env: { MCP_CLIENT_SECRET }` alone would replace
  // the whole environment).
  await promisify(spawn)(claudeFile, args, {
    env: { ...process.env, MCP_CLIENT_SECRET: client.secret },
    stdio: "inherit",
  });
};
