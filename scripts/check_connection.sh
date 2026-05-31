#!/bin/bash
set -e

# Verify the client connected to the XMPP server
if grep -q "Connected to XMPP server successfully" chatterbox.log; then
    echo "PASSED ✅ — Connected to XMPP server"
    exit 0
fi

echo "FAILED ❌ — No successful connection found in log"
echo "--- Log contents ---"
cat chatterbox.log
exit 1
