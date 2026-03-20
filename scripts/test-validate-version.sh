#!/usr/bin/env bash
# Tests for scripts/validate-version.sh

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
VALIDATE="$SCRIPT_DIR/validate-version.sh"

PKG_VERSION=$(jq -r '.version' "$SCRIPT_DIR/../package.json")
IFS='.' read -r MAJOR MINOR PATCH <<< "$PKG_VERSION"
CURRENT="v$PKG_VERSION"
NEXT_PATCH="v$MAJOR.$MINOR.$((PATCH + 1))"
PREV_PATCH="v$MAJOR.$MINOR.$((PATCH > 0 ? PATCH - 1 : 0))"

PASS=0
FAIL=0

run_test() {
  local description="$1"
  local event_name="$2"
  local version="$3"
  local expect="$4"        # "pass" or "fail"
  local pkg_version="${5:-$PKG_VERSION}"

  if EVENT_NAME="$event_name" VERSION="$version" PKG_VERSION="$pkg_version" bash "$VALIDATE" > /dev/null 2>&1; then
    actual="pass"
  else
    actual="fail"
  fi

  if [ "$actual" = "$expect" ]; then
    echo "  PASS  $description"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $description (expected $expect, got $actual)"
    FAIL=$((FAIL + 1))
  fi
}

echo "Testing validate-version.sh"
echo "  PKG_VERSION : $PKG_VERSION"
echo "  CURRENT     : $CURRENT"
echo "  NEXT_PATCH  : $NEXT_PATCH"
echo "  PREV_PATCH  : $PREV_PATCH"
echo ""

echo "release:"
run_test "valid version matching package.json"        release "$CURRENT"              pass
run_test "missing v prefix"                           release "$PKG_VERSION"          fail
run_test "has pre-release suffix"                     release "${CURRENT}-alpha.0"    fail
run_test "version ahead of package.json"              release "$NEXT_PATCH"           fail
run_test "version behind package.json"                release "$PREV_PATCH"           fail

echo ""
echo "workflow_dispatch:"
run_test "valid alpha pre-release"                    workflow_dispatch "${NEXT_PATCH}-alpha.0"   pass
run_test "valid beta pre-release"                     workflow_dispatch "${NEXT_PATCH}-beta.0"    pass
run_test "missing v prefix"                           workflow_dispatch "${NEXT_PATCH#v}-alpha.0" fail
run_test "no pre-release suffix"                      workflow_dispatch "$NEXT_PATCH"             fail
run_test "unsupported suffix (rc)"                    workflow_dispatch "${NEXT_PATCH}-rc.0"      fail
run_test "equal to package.json version (not ahead)"  workflow_dispatch "${CURRENT}-alpha.0"      fail
if [ "$PATCH" -gt 0 ]; then
  run_test "behind package.json version"              workflow_dispatch "${PREV_PATCH}-alpha.0"   fail
fi

echo ""
echo "double-digit versions:"
run_test "release with double-digit major matches"           release          "v10.0.1"         pass  "10.0.1"
run_test "release double-digit major ahead of single-digit"  release          "v10.0.1"         fail  "9.0.1"
run_test "release single-digit major behind double-digit"    release          "v9.0.1"          fail  "10.0.1"
run_test "pre-release double-digit major ahead"              workflow_dispatch "v10.0.2-alpha.0" pass  "10.0.1"
run_test "pre-release double-digit minor ahead"              workflow_dispatch "v1.10.0-alpha.0" pass  "1.9.0"
run_test "pre-release double-digit minor not ahead"          workflow_dispatch "v1.9.0-alpha.0"  fail  "1.10.0"

echo ""
echo "output:"
CAPTURED=$(EVENT_NAME=release VERSION="$CURRENT" PKG_VERSION="$PKG_VERSION" bash "$VALIDATE")
if [ "$CAPTURED" = "$CURRENT" ]; then
  echo "  PASS  echoes VERSION on success"
  PASS=$((PASS + 1))
else
  echo "  FAIL  expected '$CURRENT', got '$CAPTURED'"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
