#!/bin/bash
set -e

# Verify the OMEMO bundle was published
if grep -q "Bundle published successfully" chatterbox.log; then
    echo "PASSED ✅ — OMEMO bundle published"
    exit 0
fi

# Also accept the alternative format path
if grep -q "Key bundle published successfully" chatterbox.log; then
    echo "PASSED ✅ — OMEMO key bundle published"
    exit 0
fi

echo "FAILED ❌ — No bundle publication found in log"
echo "--- Relevant log lines ---"
grep -i "bundle\|publish\|omemo" chatterbox.log || true
exit 1
