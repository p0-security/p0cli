/** Copyright © 2024-present P0 Security

This file is part of @p0security/cli

@p0security/cli is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

@p0security/cli is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with @p0security/cli. If not, see <https://www.gnu.org/licenses/>.
**/
import { exitSignalsIntercepted, interceptExitSignals } from "../exit-signals";
import { describe, expect, it } from "vitest";

const SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"] as const;

describe("interceptExitSignals", () => {
  it.each(SIGNALS)("aborts `interrupted` on %s", (signal) => {
    const { interrupted, release } = interceptExitSignals();
    expect(interrupted.aborted).toBe(false);

    // Stands in for the signal arriving: runs the listener that was added
    (process.listeners(signal).at(-1) as () => void)();
    release();

    expect(interrupted.aborted).toBe(true);
  });

  it.each(SIGNALS)("listens for %s only until released", (signal) => {
    const before = process.listenerCount(signal);

    const { release } = interceptExitSignals();
    expect(process.listenerCount(signal)).toBe(before + 1);

    release();
    expect(process.listenerCount(signal)).toBe(before);
  });

  it("reports the signals as intercepted until every command has released them", () => {
    expect(exitSignalsIntercepted()).toBe(false);

    const first = interceptExitSignals();
    const second = interceptExitSignals();
    expect(exitSignalsIntercepted()).toBe(true);

    first.release();
    expect(exitSignalsIntercepted()).toBe(true);

    second.release();
    expect(exitSignalsIntercepted()).toBe(false);
  });
});
