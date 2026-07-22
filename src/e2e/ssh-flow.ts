/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  E2E_REASON,
  LsDestinationItem,
  lsItemMatchesNode,
  runCommand,
  runP0,
  SshTarget,
  SUCCESS_EXIT_CODE,
  uniqueMarker,
} from "./harness";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, describe, expect, it } from "vitest";

/** Registers the sequential access-lifecycle flow for a single cloud
 * provider's node: a `p0 ls` lookup, `p0 ssh`, `p0 ssh --sudo`, `p0 scp`, then
 * a plain `ssh <node-id>` through the user's own ssh config. The first
 * `p0 ssh` requests access to the node; every later step reuses that grant.
 * Each step runs a remote command instead of an interactive shell, so its
 * session ends on its own as soon as the connection succeeds.
 *
 * Call this once per provider spec file so each provider's flow can be run
 * independently (e.g. `yarn e2e src/e2e/ssh-aws.e2e.ts`). */
export const describeSshFlow = ({ provider, lsProvider, node }: SshTarget) => {
  describe.skipIf(!node)(`p0 ssh flow (${provider})`, () => {
    const marker = uniqueMarker(`flow-${provider}`);
    const localDir = fs.mkdtempSync(
      path.join(os.tmpdir(), `p0-e2e-flow-${provider}-`)
    );
    const uploadPath = path.join(localDir, "upload.txt");
    const downloadPath = path.join(localDir, "download.txt");
    const remotePath = `/tmp/${marker}.txt`;

    afterAll(async () => {
      fs.rmSync(localDir, { recursive: true, force: true });
      // Best-effort remote cleanup; not part of the assertion.
      await runP0(
        [
          "ssh",
          node!,
          "--provider",
          provider,
          "--reason",
          E2E_REASON,
          "rm",
          "-f",
          remotePath,
        ],
        { timeoutMs: 5 * 60_000 }
      );
    });

    it("finds the configured node via p0 ls before requesting access", async () => {
      const result = await runP0(
        ["ls", "ssh", "session", "destination", "--json", "--size", "500"],
        { timeoutMs: 2 * 60_000 }
      );
      expect(result.code, result.output).toBe(SUCCESS_EXIT_CODE);

      const { items } = JSON.parse(result.stdout) as {
        items: LsDestinationItem[];
      };
      const found = items.some((item) =>
        lsItemMatchesNode(item, lsProvider, node!)
      );
      expect(
        found,
        `${node} was not found among ${lsProvider} destinations in \`p0 ls ssh session destination\`; is it visible to the e2e user?\n${result.output}`
      ).toBe(true);
    });

    it("requests access with p0 ssh and runs a command", async () => {
      const result = await runP0([
        "ssh",
        node!,
        "--provider",
        provider,
        "--reason",
        E2E_REASON,
        "echo",
        marker,
      ]);

      expect(result.code, result.output).toBe(SUCCESS_EXIT_CODE);
      expect(result.output).toContain(marker);
    });

    it("reconnects with p0 ssh --sudo and runs a command as root", async () => {
      const result = await runP0([
        "ssh",
        node!,
        "--provider",
        provider,
        "--sudo",
        "--reason",
        E2E_REASON,
        "sudo",
        "whoami",
      ]);

      expect(result.code, result.output).toBe(SUCCESS_EXIT_CODE);
      expect(result.output).toContain("root");
    });

    it("uploads and downloads a file round trip with p0 scp", async () => {
      fs.writeFileSync(uploadPath, `${marker}\n`);

      const upload = await runP0([
        "scp",
        uploadPath,
        `${node!}:${remotePath}`,
        "--provider",
        provider,
        "--reason",
        E2E_REASON,
      ]);
      expect(upload.code, upload.output).toBe(SUCCESS_EXIT_CODE);

      const download = await runP0([
        "scp",
        `${node!}:${remotePath}`,
        downloadPath,
        "--provider",
        provider,
        "--reason",
        E2E_REASON,
      ]);
      expect(download.code, download.output).toBe(SUCCESS_EXIT_CODE);

      expect(fs.readFileSync(downloadPath, "utf8")).toBe(`${marker}\n`);
    });

    it("connects with a plain `ssh <node-id>` through the user's ssh config", async () => {
      // The Match exec line runs `p0 ssh-resolve`, which writes the node's
      // config under P0_PATH; the Include then applies its `p0 ssh-proxy`
      // ProxyCommand — the native-ssh setup end to end.
      const sshMarker = uniqueMarker(`flow-${provider}-native-ssh`);
      const ssh = await runCommand("ssh", [node!, `echo ${sshMarker}`]);

      expect(ssh.code, ssh.output).toBe(SUCCESS_EXIT_CODE);
      expect(ssh.output).toContain(sshMarker);
    });
  });
};
