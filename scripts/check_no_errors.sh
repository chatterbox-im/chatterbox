#!/bin/bash
set -e

# Check that no ERROR-level log lines appear (excluding known benign ones)
# Known benign:
#   - "item-not-found" on first publish (no existing node)
#   - connection close / stream end on timeout kill
#   - device list timeout (PubSub response may not arrive within headless run)
ERRORS=$(grep " ERROR " chatterbox.log \
    | grep -v "item-not-found" \
    | grep -v "connection closed" \
    | grep -v "stream ended" \
    | grep -v "disconnected" \
    | grep -v "Timeout while fetching device list" \
    || true)

if [ -z "$ERRORS" ]; then
    echo "PASSED ✅ — No unexpected errors in log"
    exit 0
fi

echo "FAILED ❌ — Unexpected errors found:"
echo "$ERRORS"
exit 1
