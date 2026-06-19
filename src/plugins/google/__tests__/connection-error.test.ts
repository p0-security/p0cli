/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import {
  classifyGcpConnectionError,
  GCP_SSH_PREREQUISITES_DOC,
} from "../connection-error";
import { describe, expect, it } from "vitest";

const REQUEST = { id: "my-instance" };

// Sample stderr captured from real connection attempts. Both the gcloud IAP
// tunnel (the SSH ProxyCommand) and the SSH process write to the same stream,
// so each sample mixes verbose SSH lines with gcloud output as observed.

/** OS Login off: the tunnel established (SSH auth was reached) but the user's
 * key was never provisioned onto the VM, so auth is rejected. */
const PUBLICKEY_DENIED_STDERR = `
debug1: Connecting to 127.0.0.1 [127.0.0.1] port 22.
debug1: Authentications that can continue: publickey
debug1: No more authentication methods to try.
my-user@my-instance: Permission denied (publickey).
`;

/** A tunnel error followed, after the IAP role propagated, by an auth rejection.
 * The terminal cause is auth (reaching it proves the tunnel works). */
const MIXED_TUNNEL_THEN_PUBLICKEY_STDERR = `
Error while connecting [4033: 'not authorized'].
debug1: Authenticated to nothing.
my-user@my-instance: Permission denied (publickey).
`;

/** IAP / firewall not configured: gcloud cannot reach the backend, so the tunnel
 * never establishes and SSH auth is never attempted. We intentionally do not
 * classify this — it falls through to the raw error. */
const IAP_BACKEND_FAILURE_STDERR = `
ERROR: (gcloud.compute.start-iap-tunnel) Error while connecting [4003: 'failed to connect to backend']. (Failed to connect to port 22)
kex_exchange_identification: Connection closed by remote host
`;

describe("classifyGcpConnectionError", () => {
  describe("OS Login / auth failures", () => {
    it("classifies a publickey rejection as a likely OS Login problem", () => {
      const message = classifyGcpConnectionError(
        PUBLICKEY_DENIED_STDERR,
        REQUEST
      );
      expect(message).toBeDefined();
      expect(message).toContain("Connected to my-instance");
      expect(message).toContain("Permission denied (publickey)");
      expect(message).toContain("enable-oslogin=TRUE");
      expect(message).toContain("most common cause is OS Login");
      // Does not claim OS Login is definitively off — lists the alternatives.
      expect(message).toContain("key-propagation delay");
      expect(message).toContain("just-granted IAM role");
      expect(message).toContain(GCP_SSH_PREREQUISITES_DOC);
    });

    it("classifies as OS Login when auth was reached, even if an earlier tunnel error is present", () => {
      const message = classifyGcpConnectionError(
        MIXED_TUNNEL_THEN_PUBLICKEY_STDERR,
        REQUEST
      );
      // Reaching publickey auth proves the tunnel established, so this is the OS
      // Login path.
      expect(message).toContain("most common cause is OS Login");
    });
  });

  describe("passthrough", () => {
    it("does not classify an IAP / tunnel-establishment failure (left to the raw error)", () => {
      expect(
        classifyGcpConnectionError(IAP_BACKEND_FAILURE_STDERR, REQUEST)
      ).toBeUndefined();
    });

    it("returns undefined for an unrecognized error", () => {
      const stderr = `
ssh: connect to host my-instance port 22: Network is unreachable
debug1: some unrelated verbose output
`;
      expect(classifyGcpConnectionError(stderr, REQUEST)).toBeUndefined();
    });

    it("returns undefined for empty stderr", () => {
      expect(classifyGcpConnectionError("", REQUEST)).toBeUndefined();
    });

    it("does not match a benign host-key warning as a prerequisite failure", () => {
      const stderr =
        "Warning: Permanently added 'my-instance' to the list of known hosts.";
      expect(classifyGcpConnectionError(stderr, REQUEST)).toBeUndefined();
    });
  });
});
