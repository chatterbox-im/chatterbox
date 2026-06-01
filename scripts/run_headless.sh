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
HEADLESS_DIR="${CHATTERBOX_HEADLESS_DIR:-$PWD/target/headless}"

if [ ! -f "$BINARY" ]; then
    echo "Binary not found at $BINARY — run 'cargo build' first"
    exit 1
fi

# Clean previous log
mkdir -p "$HEADLESS_DIR"
rm -f "$LOG_FILE" "$HEADLESS_DIR/chatterbox.log"

echo "Running chatterbox for ${DURATION}s..."
if [ -t 0 ] && [ -t 1 ]; then
    timeout "${DURATION}s" "$BINARY" --omemo-dir "$HEADLESS_DIR" || true
elif command -v script >/dev/null 2>&1; then
    # The TUI requires a terminal. CI stdout/stdin are not TTYs, so run it
    # under a pseudo-terminal while keeping logs/config in a predictable dir.
    if script --version >/dev/null 2>&1; then
        printf -v COMMAND '%q ' "$BINARY" --omemo-dir "$HEADLESS_DIR"
        TERM="${TERM:-xterm-256color}" timeout "${DURATION}s" script -q -e -c "$COMMAND" /dev/null || true
    else
        TERM="${TERM:-xterm-256color}" timeout "${DURATION}s" script -q /dev/null "$BINARY" --omemo-dir "$HEADLESS_DIR" || true
    fi
else
    echo "WARNING: no TTY and no script(1) available; running directly may fail"
    timeout "${DURATION}s" "$BINARY" --omemo-dir "$HEADLESS_DIR" || true
fi

if [ -f "$HEADLESS_DIR/chatterbox.log" ]; then
    cp "$HEADLESS_DIR/chatterbox.log" "$LOG_FILE"
fi

if [ ! -f "$LOG_FILE" ]; then
    echo "ERROR: No log file produced"
    exit 1
fi

echo "Done. Log has $(wc -l < "$LOG_FILE") lines."
