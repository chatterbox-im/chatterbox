#!/bin/bash
set -e

# Run chatterbox headless for a fixed duration, capturing logs.
# Used by CI to verify startup, connection, and OMEMO init.
#
# Usage: ./scripts/run_headless.sh [SECONDS]
#   SECONDS: how long to run (default: 30)

DURATION=${1:-30}
BINARY="./target/debug/chatterbox"
LOG_FILE="chatterbox.log"

if [ ! -f "$BINARY" ]; then
    echo "Binary not found at $BINARY — run 'cargo build' first"
    exit 1
fi

# Clean previous log
rm -f "$LOG_FILE"

echo "Running chatterbox for ${DURATION}s..."
timeout "${DURATION}s" "$BINARY" || true

if [ ! -f "$LOG_FILE" ]; then
    echo "ERROR: No log file produced"
    exit 1
fi

echo "Done. Log has $(wc -l < "$LOG_FILE") lines."
