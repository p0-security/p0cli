#!/usr/bin/env bash
# Validates VERSION against the package.json version.
#
# Inputs (environment variables):
#   VERSION     - the version to validate (e.g. v0.26.1-alpha.0 or v0.26.1)
#   EVENT_NAME  - the GitHub Actions event name (workflow_dispatch or release)
#   PKG_VERSION - the current version from package.json (e.g. 0.26.1)
#
# On success, echoes VERSION so callers can capture it as an output.

set -euo pipefail
NUMERIC_VERSION="${VERSION#v}"
NUMERIC_VERSION="${NUMERIC_VERSION%%-*}"

version_gt() {
  [ "$(printf '%s\n' "$1" "$2" | sort -V | head -1)" != "$1" ]
}

if [[ "$EVENT_NAME" == "workflow_dispatch" ]]; then
  if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta)\.[0-9]+$ ]]; then
    echo "Error: workflow_dispatch version must have a v prefix and alpha or beta pre-release suffix, e.g. v0.26.1-alpha.0" >&2
    exit 1
  fi
  if ! version_gt "$NUMERIC_VERSION" "$PKG_VERSION"; then
    echo "Error: pre-release version $NUMERIC_VERSION must be greater than package.json version $PKG_VERSION" >&2
    exit 1
  fi
else
  if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: release version must have a v prefix and no pre-release suffix, e.g. v0.26.1" >&2
    exit 1
  fi
  if [ "$NUMERIC_VERSION" != "$PKG_VERSION" ]; then
    echo "Error: release version $NUMERIC_VERSION must match package.json version $PKG_VERSION" >&2
    exit 1
  fi
fi

echo "$VERSION"
