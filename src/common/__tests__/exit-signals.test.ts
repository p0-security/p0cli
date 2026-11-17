/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { exitSignalsIntercepted, interruptOnExitSignal } from "../exit-signals";
import { describe, expect, it } from "vitest";

const SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"] as const;

// Stands in for the signal arriving: runs the listener that was added last
const sendSignal = (signal: NodeJS.Signals) =>
  (process.listeners(signal).at(-1) as () => void)();

/** Work that only ends once it is interrupted */
const untilInterrupted = (interrupted: AbortSignal) =>
  new Promise<string>((resolve) =>
    interrupted.addEventListener("abort", () => resolve("interrupted"))
  );

describe("interruptOnExitSignal", () => {
  it("returns what the work returns", async () => {
    await expect(interruptOnExitSignal(async () => "done")).resolves.toBe(
      "done"
    );
  });

  it.each(SIGNALS)("interrupts the work on %s", async (signal) => {
    const result = interruptOnExitSignal(untilInterrupted);

    sendSignal(signal);

    await expect(result).resolves.toBe("interrupted");
  });

  it.each(SIGNALS)(
    "listens for %s only while the work runs",
    async (signal) => {
      const before = process.listenerCount(signal);

      await interruptOnExitSignal(async () => {
        expect(process.listenerCount(signal)).toBe(before + 1);
      });

      expect(process.listenerCount(signal)).toBe(before);
    }
  );

  it("reports the signals as intercepted only while the work runs", async () => {
    expect(exitSignalsIntercepted()).toBe(false);

    await interruptOnExitSignal(async () => {
      expect(exitSignalsIntercepted()).toBe(true);
    });

    expect(exitSignalsIntercepted()).toBe(false);
  });

  it("hands the signals back when the work fails", async () => {
    await expect(
      interruptOnExitSignal(async () => {
        throw "Access did not propagate";
      })
    ).rejects.toBe("Access did not propagate");

    expect(exitSignalsIntercepted()).toBe(false);
  });
});
