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
import spawn from "cross-spawn";
import assert from "node:assert";
import { exec } from "node:child_process";
import fs from "node:fs/promises";
import { hostname as osHostname } from "node:os";
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
};

type CachedMcpClient = CreateMcpClientResp & {
  orgSlug: string;
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
  force: boolean | undefined;
  scope: string | undefined;
  server: string;
}>;

const CLIENT_PATH = postfixPath("claude/mcp-client.json");

const REDIRECT_PORT = 8080;

export const mcpCommand = (yargs: yargs.Argv<{ debug?: boolean }>) =>
  yargs
    .demandCommand(1)
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
          })
          .option("force", {
            alias: "f",
            describe: "Discard any cached MCP client and register a new one",
            type: "boolean",
            default: false,
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
  print2(`Registered MCP server '${argv.server}' with Claude Code.`);
};

const createClient = async (authn: Authn, argv: AddMcpServerArgs) => {
  const version = (await promisify(exec)("claude --version")).stdout.trim();
  const hostname = osHostname();

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
  const cachedClientData = {
    ...clientData,
    orgSlug: authn.identity.org.slug,
  } satisfies CachedMcpClient;

  await fs.writeFile(CLIENT_PATH, JSON.stringify(cachedClientData, null, 2), {
    mode: "400",
  });

  return cachedClientData;
};

const ensureClient = async (authn: Authn, argv: AddMcpServerArgs) => {
  if (argv.force) {
    debug(
      argv,
      "Forcing fresh client registration (ignoring",
      CLIENT_PATH,
      ")"
    );
    return await createClient(authn, argv);
  }

  try {
    const cachedClientData = await fs.readFile(CLIENT_PATH, {
      encoding: "utf-8",
    });

    if (cachedClientData) {
      const client = JSON.parse(cachedClientData) as Partial<CachedMcpClient>;
      if (client.orgSlug !== authn.identity.org.slug) {
        debug(
          argv,
          "Ignoring cached client at",
          CLIENT_PATH,
          "for org",
          client.orgSlug ?? "<unknown>",
          "while authenticated to",
          authn.identity.org.slug
        );
        return await createClient(authn, argv);
      }
      if (!client.client) {
        debug(argv, "Ignoring invalid cached client at", CLIENT_PATH);
        return await createClient(authn, argv);
      }
      const usableClient = {
        orgSlug: client.orgSlug,
        client: client.client,
      } satisfies CachedMcpClient;
      const cachedPort = Number(
        usableClient.client.redirectUri.split(":").at(-1)
      );
      const requestedPort = argv.callbackPort ?? REDIRECT_PORT;
      if (cachedPort !== requestedPort) {
        print2(
          `Warning: cached MCP client was registered for callback port ${cachedPort}, but --callback-port=${requestedPort} was requested. Using the cached port; pass --force to re-register on a new port.`
        );
      }
      debug(
        argv,
        "Using cached client at",
        CLIENT_PATH,
        "(pass --force to register a new MCP client)"
      );
      return usableClient;
    }
  } catch (error: unknown) {
    debug(argv, `Could not read client data file: ${String(error)}`);
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
  // Secret is passed via MCP_CLIENT_SECRET env (signaled by bare `--client-secret`)
  // to keep it out of the process argv list.
  const args = [
    "mcp",
    "add-json",
    server.id,
    JSON.stringify({
      type: "http",
      url: server.url,
      oauth: {
        clientId: client.id,
        callbackPort: Number(client.redirectUri.split(":").at(-1)),
      },
    }),
    ...(argv.scope ? ["--scope", argv.scope] : []),
    "--client-secret",
  ];
  debug(argv, ["claude", ...args].join(" "));

  await new Promise<void>((resolve, reject) => {
    const proc = spawn(claudeFile, args, {
      env: { ...process.env, MCP_CLIENT_SECRET: client.secret },
      stdio: "inherit",
    });
    proc.on("error", reject);
    proc.on("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`claude mcp add-json exited with code ${code}`));
    });
  });
};
