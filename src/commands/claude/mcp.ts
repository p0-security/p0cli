/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { authFetch, tenantUrl } from "../../drivers/api";
import { authenticate } from "../../drivers/auth";
import { postfixPath } from "../../drivers/auth/path";
import { debug } from "../../drivers/stdio";
import { Authn } from "../../types/identity";
import assert from "node:assert";
import { exec, spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import yargs from "yargs";

type CreateMcpClientReq = {
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

type AddMcpServerArgs = yargs.ArgumentsCamelCase<{
  debug?: boolean;
  callbackPort: number | undefined;
  scope: string | undefined;
  server: string;
}>;

const CLIENT_PATH = postfixPath("claude/mcp-client.json");

const REDIRECT_PORT = 8080;

export const mcpCommand = (yargs: yargs.Argv<{ debug?: boolean }>) =>
  yargs.command(
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
  );

const handleAddMcpServer = async (argv: AddMcpServerArgs) => {
  const authn = await authenticate();

  if (!argv.server) {
    throw "'server' is required";
  }

  const client = await ensureClient(authn, argv);
  const server = await getServer(authn, argv);

  await provisionServer(argv, client, server);
};

const createClient = async (authn: Authn, argv: AddMcpServerArgs) => {
  const version = (await promisify(exec)("claude --version")).stdout;

  const clientData = await authFetch<CreateMcpClientResp>(authn, {
    url: `${tenantUrl(authn.identity.org.slug)}/mcp/clients`,
    method: "POST",
    body: JSON.stringify({
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
      return client;
    }
  } catch (error: unknown) {
    debug(argv, `Could not read client data file: String(error)`);
  }

  return await createClient(authn, argv);
};

const getServer = async (authn: Authn, argv: AddMcpServerArgs) =>
  await authFetch<GetMcpServerResp>(authn, {
    url: `${tenantUrl(authn.identity.org.slug)}/mcp/servers/${argv.server}`,
    method: "GET",
  });

const provisionServer = async (
  argv: AddMcpServerArgs,
  { client }: CreateMcpClientResp,
  { server }: GetMcpServerResp
) => {
  const claudeFile = (await promisify(exec)("which claude")).stdout.trim();
  assert(client.secret, "No client secret");
  const args = [
    "mcp",
    "add-json",
    server.id,
    JSON.stringify({
      type: "http",
      url: server.url,
      oauth: {
        clientId: client.id,
        clientSecret: client.secret,
        callbackPort: Number(client.redirectUri.split(":").at(-1)!),
      },
    }),
    ...(argv.scope ? ["--scope", argv.scope] : []),
    "--client-secret",
  ];
  debug(argv, "Client secret", client.secret);
  debug(argv, ["claude", ...args].join(" "));
  await promisify(spawn)(claudeFile, args, {
    env: { MCP_CLIENT_SECRET: client.secret },
    stdio: "inherit",
  });
};
