# P0 CLI end-to-end tests

Automated end-to-end tests that exercise the real CLI against a live P0 organization (default: `p0-e2e`) and real cloud nodes. They are entirely separate from the unit tests (`yarn test:unit`).

```
yarn e2e
```

Target a single cloud provider's flow by passing its spec file (see "What it does" below for the file names):

```
yarn e2e src/e2e/ssh-aws.e2e.ts
yarn e2e src/e2e/ssh-azure.e2e.ts
yarn e2e src/e2e/ssh-gcloud.e2e.ts
```

Global setup and login still run first; only that provider's node needs to be configured (see Configuration below).

## What it does

Global setup (before any test) smoke-tests the existing build with `p0 --version` and runs `p0 login p0-e2e` — a failure of either step aborts the whole run. Run `yarn build` yourself first; the suite does not build for you.

There's one ssh flow spec per cloud provider — `ssh-aws.e2e.ts`, `ssh-azure.e2e.ts`, `ssh-gcloud.e2e.ts` — each driving its configured node through the whole access lifecycle, in order. They share their step logic (`ssh-flow.ts`) but are separate files so you can run one provider independently, e.g. `yarn e2e src/e2e/ssh-aws.e2e.ts`. Each step runs a remote command instead of an interactive shell, so its session ends on its own once the connection succeeds:

1. `p0 ls ssh session destination --json` — confirms the configured node is visible to the e2e user (matched by key, value, instance ID, name, or alternative name) before spending time requesting access to it
2. `p0 ssh <node-id> --provider <p>` — requests access to the node (waits for approval and propagation), connects, runs a command
3. `p0 ssh <node-id> --provider <p> --sudo` — reconnects with a sudo grant, runs a command as root
4. `p0 scp` — upload/download round trip
5. plain `ssh <node-id>` — the system ssh resolves the node through your own ssh config: a `Match exec` line runs `p0 ssh-resolve`, and an `Include` picks up the generated config whose ProxyCommand drives `p0 ssh-proxy`

Step 5 requires your `~/.ssh/config` to delegate to this repository's CLI — set it up before running the suite by adding these lines:

```
Match exec "<repo>/p0 ssh-resolve %h"
Include <P0_PATH>/ssh/configs/*.config
```

(`<P0_PATH>` is `~/.p0` or `~/.p0-<env>` depending on your CLI environment; extra `ssh-resolve` flags such as `--debug` are fine, but the `Match` line must come before the `Include`.)

At the end of the run the suite prints a reminder: **please revoke all access granted to the e2e user before running the suite again**, so the next run requests access from scratch.

## Configuration

Set node IDs via environment variables, or put them in a git-ignored `.env` file at the repository root:

```
P0_E2E_AWS_NODE=my-aws-instance
P0_E2E_AZURE_NODE=my-azure-vm
P0_E2E_GCLOUD_NODE=my-gcp-instance

# Optional overrides
P0_E2E_ORG=p0-e2e
P0_E2E_REASON=P0 CLI automated e2e test
```

Each provider's flow is skipped with a warning when its node is not configured — set as many or as few as you have access to. Set `P0_E2E_SKIP_SETUP=1` to reuse the existing login session when iterating on individual specs.

## Prerequisites

- A build: run `yarn build` before `yarn e2e` (and again after pulling in CLI changes — the suite does not rebuild for you).
- A user for the e2e org whose access requests are auto-approved (a first run may open a browser to complete login).
- All access for the e2e user revoked, so each flow exercises fresh requests.
- Your `~/.ssh/config` delegating to this repository's CLI (see "The ssh flow" above).
- Cloud CLIs installed for the providers under test (`aws` + session-manager plugin, `az`, `gcloud`), plus a system `ssh`/`scp`.
- Expect long runtimes: access propagation can take several minutes per provider; individual tests time out after 20 minutes.

Tests against real cloud infra hit occasional transient failures (propagation timing, intermittent connection errors), so each test retries up to 3 times before failing the run (see `retry` in `vitest.e2e.config.mts`).
