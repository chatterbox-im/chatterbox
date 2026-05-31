#!/bin/bash
set -e

# Run the bidirectional OMEMO message exchange integration test.
# Requires: XMPP_SERVER, XMPP_USERNAME, XMPP_PASSWORD, XMPP_USERNAME_B, XMPP_PASSWORD_B

REQUIRED_VARS="XMPP_SERVER XMPP_USERNAME XMPP_PASSWORD XMPP_USERNAME_B XMPP_PASSWORD_B"

for var in $REQUIRED_VARS; do
    if [ -z "${!var}" ]; then
        echo "SKIPPED — $var not set"
        exit 0
    fi
done

echo "Running bidirectional OMEMO exchange test..."
echo "  Server: $XMPP_SERVER"
echo "  User A: $XMPP_USERNAME"
echo "  User B: $XMPP_USERNAME_B"

cargo test --test omemo_bidirectional_test -- --ignored --nocapture 2>&1
echo "PASSED ✅ — Bidirectional OMEMO message exchange"
