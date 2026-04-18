#!/bin/bash
# TA-cveicu Test Bench
#
# Usage:
#   ./test.sh              Run unit tests only (fast, no Docker)
#   ./test.sh unit         Run unit tests only
#   ./test.sh integration  Run integration tests (starts Docker Splunk)
#   ./test.sh all          Run all tests
#   ./test.sh live         Run all tests including live API tests
#   ./test.sh package      Build package and run AppInspect
#
# Requirements:
#   - Python 3.11+ with pytest: pip install -r requirements-dev.txt
#   - Docker (for integration/live tests)
#   - splunk-appinspect (for package test): pip install splunk-appinspect

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() { echo -e "${GREEN}PASS${NC} $1"; }
fail() { echo -e "${RED}FAIL${NC} $1"; }
info() { echo -e "${YELLOW}INFO${NC} $1"; }

MODE="${1:-unit}"

case "$MODE" in
  unit)
    info "Running unit tests..."
    python -m pytest tests/unit/ -v
    ;;

  integration)
    info "Running integration tests (starting Docker Splunk)..."
    info "This will take a few minutes for Splunk to start."
    python -m pytest tests/integration/ -v -x
    ;;

  all)
    info "Running unit tests..."
    python -m pytest tests/unit/ -v
    echo ""
    info "Running integration tests (starting Docker Splunk)..."
    python -m pytest tests/integration/ -v -x
    ;;

  live)
    info "Running ALL tests including live API tests..."
    python -m pytest tests/ -v --live -x
    ;;

  package)
    info "Building and validating package..."

    # Determine version from app.conf
    VERSION=$(grep 'version' TA-cveicu/default/app.conf | head -1 | awk -F'= ' '{print $2}' | tr -d ' ')
    PACKAGE="TA-cveicu-${VERSION}.tar.gz"

    info "Building ${PACKAGE}..."
    COPYFILE_DISABLE=1 tar -czf "$PACKAGE" --exclude='.*' TA-cveicu/

    if command -v splunk-appinspect &> /dev/null; then
      info "Running AppInspect precert validation..."
      OUTPUT=$(splunk-appinspect inspect "$PACKAGE" --mode precert 2>&1)
      FAILURES=$(echo "$OUTPUT" | grep -c '^\[  F  \]' || true)
      ERRORS=$(echo "$OUTPUT" | grep -c '^\[  E  \]' || true)

      echo "$OUTPUT" | tail -12
      echo ""

      if [ "$FAILURES" -gt 0 ] || [ "$ERRORS" -gt 0 ]; then
        fail "AppInspect: ${FAILURES} failures, ${ERRORS} errors"
        echo ""
        echo "Failure details:"
        echo "$OUTPUT" | grep -A3 '^\[  F  \]'
        exit 1
      else
        pass "AppInspect: 0 failures, 0 errors"
      fi
    else
      info "splunk-appinspect not installed, skipping validation."
      info "Install with: pip install splunk-appinspect"
    fi

    pass "Package built: ${PACKAGE}"
    ;;

  *)
    echo "Usage: $0 {unit|integration|all|live|package}"
    exit 1
    ;;
esac
