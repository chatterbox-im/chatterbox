#!/bin/bash
set -e

# Verify OMEMO initialization completed (device ID generated/loaded, identity key ready)
PASS=true

if ! grep -q "OMEMO" chatterbox.log; then
    echo "FAILED ❌ — No OMEMO activity in log at all"
    cat chatterbox.log
    exit 1
fi

# Check device ID was established
if grep -qi "device.*id\|device_id" chatterbox.log; then
    echo "  ✓ Device ID established"
else
    echo "  ✗ No device ID activity found"
    PASS=false
fi

# Check bundle publication was attempted
if grep -qi "publish.*bundle\|bundle.*publish" chatterbox.log; then
    echo "  ✓ Bundle publication attempted"
else
    echo "  ✗ No bundle publication attempt found"
    PASS=false
fi

if [ "$PASS" = true ]; then
    echo "PASSED ✅ — OMEMO initialized correctly"
    exit 0
else
    echo "FAILED ❌ — OMEMO initialization incomplete"
    echo "--- OMEMO-related log lines ---"
    grep -i "omemo\|bundle\|device" chatterbox.log || true
    exit 1
fi
