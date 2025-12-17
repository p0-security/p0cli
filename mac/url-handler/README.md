# P0 URL Handler

A minimal macOS application that registers the `p0://` URL scheme and bridges browser-initiated actions to the P0 CLI, allowing users to click links in their browser and automatically launch P0 CLI commands in Terminal.

## How It Works

When a user clicks a `p0://` URL in their browser or any application, macOS Launch Services routes the URL to this handler, which parses the URL, locates the P0 CLI binary, and launches Terminal with the appropriate command.

**URL Format:**
```
p0://command/resource/subresource?param1=value1&param2=value2
```

Query parameters are converted to CLI flags (`--param=value`), and boolean flags without values become `--flag`.

Note: when including parameters with URL-encoded whitespace, URL-encoded single or double quotes are not required.


## Usage Examples

| URL | CLI Command |
|-----|-------------|
| `p0://ssh/my-host` | `p0 ssh my-host` |
| `p0://request/aws/role/admin` | `p0 request aws role admin` |
| `p0://ssh/prod-db-01?user=admin&port=2222` | `p0 ssh prod-db-01 --user=admin --port=2222` |
| `p0://aws/role/assume/developer?reason=debugging` | `p0 aws role assume developer --reason=debugging` |
| `p0://ssh/my-host?reason=urgent%20maintenance` | `p0 ssh my-host --reason="urgent maintenance"` |


## Project Structure

```
mac/
├── url-handler.xcodeproj/       # Xcode project (managed by Xcode, don't edit manually)
│   └── project.pbxproj          # Project configuration
├── url-handler/                 # Source files
│   ├── app.swift                # Main application logic and entry point
│   ├── utils.swift              # URL parsing, CLI discovery, Terminal launch
│   ├── util-tests.swift         # Unit tests for URL parsing
│   ├── Assets.xcassets/         # App icon assets
│   ├── Info.plist               # Bundle configuration: registers p0:// scheme, hides from Dock
│   ├── url-handler.entitlements # App-specific entitlements
│   └── README.md                # This file
├── entitlements.plist           # macOS entitlements
└── build-macOS.sh               # Build script for CLI and URL handler
```

## Building

The URL handler is automatically built as part of the P0 CLI macOS build:

```bash
# From repository root
yarn build:macos
./mac/build-macOS.sh
```

## Running Tests

**Command line:**
```bash
xcodebuild test -project mac/url-handler.xcodeproj -scheme url-handler -destination 'platform=macOS'
```

**From Xcode:**
```bash
open mac/url-handler.xcodeproj
# Then press ⌘U or select Product → Test
```

Tests validate URL parsing including path components, query parameters, edge cases, and URL encoding.

## Installation

The URL handler is automatically installed to `/Applications/P0 CLI.app` when using the P0 CLI standalone macOS installer (`.pkg`).

**Manual installation:**
```bash
# Copy to Applications
cp -R build/P0 CLI.app /Applications/

# Open once to register the URL handler
open /Applications/P0 CLI.app

# Test it
open "p0://ssh/my-host"
```

## CLI Location

The handler expects the P0 CLI to be installed at `/usr/local/bin/p0`. This location is used by the standalone macOS installer.

If the CLI is not found at this location, the handler displays an error message.

## Debugging & Logs

The URL handler logs to both the macOS unified logging system and process-specific log files for easy debugging.

### Viewing Logs from the Most Recent Invocation

**Option 1: View the log file**

Each invocation creates a unique log file at `/tmp/p0-{PID}.log`:

```bash
# If you only need the most recent PID, it is embedded in the filename (use the top result):
ls -t /tmp/p0-*.log

# Print the most recent log file
cat $(ls -t /tmp/p0-*.log 2>/dev/null | head -1)
```

**Option 2: View unified logs**

For more detailed MacOS system logs:

```bash
# This prints enough lines to show all of the logs from the last invocation
# Modify --last <time> or tail -n <number> if needed
log show --predicate 'subsystem == "dev.p0.cli.urlhandler"' --last 1h | tail -n 200

# The previous command also prints the PID of the last invocation as part of the structured logging
# You can filter on that as well for just the most recent invocation
log show --predicate 'subsystem == "dev.p0.cli.urlhandler" AND processID == <pid>' --last 1h
```

## Troubleshooting

**URL handler not working?**
```bash
# Re-register
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -kill -r -domain local -domain system -domain user
open /Applications/P0 CLI.app
```

**Terminal doesn't open?**
Grant automation permissions: System Settings → Privacy & Security → Automation → p0 → Terminal

**CLI not found?**
The handler expects the CLI at `/usr/local/bin/p0`. Verify with: `ls -la /usr/local/bin/p0`
