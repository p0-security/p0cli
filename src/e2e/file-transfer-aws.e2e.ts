/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  AWS_TARGET,
  E2E_REASON,
  LsDestinationItem,
  lsItemMatchesNode,
  runP0,
  SUCCESS_EXIT_CODE,
  uniqueMarker,
} from "./harness";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, describe, expect, it } from "vitest";

// `p0 file-transfer` only supports AWS destinations today, so this suite is a
// single spec instead of the per-provider flow/spec split the ssh suite uses.
// It targets the ssh suite's AWS node (P0_E2E_AWS_NODE): the transfer
// destination is the same instance, and the flow implicitly provisions ssh
// access to it.
const { provider, lsProvider, node } = AWS_TARGET;

describe.skipIf(!node)("p0 file-transfer flow (aws)", () => {
  const marker = uniqueMarker("file-transfer");
  const localDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "p0-e2e-file-transfer-")
  );
  // The marker doubles as the file name, so the remote path is unique per run
  // and the downloaded content is greppable.
  const sourcePath = path.join(localDir, `${marker}.txt`);

  /** Remote path reported by the transfer step; later steps verify and clean
   * up that exact path. */
  let remotePath: string | undefined;

  afterAll(async () => {
    fs.rmSync(localDir, { recursive: true, force: true });
    // Best-effort remote cleanup; not part of the assertion, so a failure
    // only logs a warning.
    if (remotePath) {
      const cleanup = await runP0(
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
      if (cleanup.code !== SUCCESS_EXIT_CODE) {
        process.stderr.write(
          `[e2e] warning: failed to remove ${remotePath} from ${node}; remove it manually\n${cleanup.output}\n`
        );
      }
    }
  });

  it("finds the configured node via p0 ls before requesting access", async () => {
    const result = await runP0(
      [
        "ls",
        "file-transfer",
        "session",
        "destination",
        "--json",
        "--size",
        "500",
      ],
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
      `${node} was not found among ${lsProvider} destinations in \`p0 ls file-transfer session destination\`; is it visible to the e2e user?\n${result.output}`
    ).toBe(true);
  });

  it("fails fast when the source file does not exist", async () => {
    // The source check runs before the access request, so a bad path must
    // fail quickly without spending an approval.
    const result = await runP0(
      [
        "file-transfer",
        path.join(localDir, "does-not-exist.txt"),
        node!,
        "--reason",
        E2E_REASON,
      ],
      { timeoutMs: 2 * 60_000 }
    );
    expect(result.code, result.output).not.toBe(SUCCESS_EXIT_CODE);
    expect(result.output).toContain("Source file not found");
  });

  it("requests access with p0 file-transfer and puts the file on the instance", async () => {
    fs.writeFileSync(sourcePath, `${marker}\n`);

    const result = await runP0([
      "file-transfer",
      sourcePath,
      node!,
      "--reason",
      E2E_REASON,
    ]);

    expect(result.code, result.output).toBe(SUCCESS_EXIT_CODE);
    expect(result.output).toContain("File transfer succeeded");

    // "Downloaded to /home/<user>/<file>. File transfer succeeded." names the
    // remote path the file landed on.
    remotePath = result.output.match(
      /Downloaded to (\S+)\. File transfer succeeded/
    )?.[1];
    expect(
      remotePath,
      `the transfer did not report a remote path\n${result.output}`
    ).toBeTruthy();
  });

  it("verifies the remote file content over p0 ssh", async () => {
    // Reuses the ssh grant the transfer step provisioned.
    expect(remotePath, "the transfer step did not run or failed").toBeTruthy();

    const result = await runP0([
      "ssh",
      node!,
      "--provider",
      provider,
      "--reason",
      E2E_REASON,
      "cat",
      remotePath!,
    ]);

    expect(result.code, result.output).toBe(SUCCESS_EXIT_CODE);
    expect(result.output).toContain(marker);
  });
});
