#!/bin/bash
set -ex

# Clean up any old logs
rm -f chatterbox.log

# 0. Run as cb to publish their bundle and device list, then disconnect
export XMPP_SERVER="xmpp.server.org"
export XMPP_USERNAME="cb"
export XMPP_PASSWORD="+ng0APPS2TCL1rTeWZjXA1ULFz5ns35"

(
    timeout 30s expect <<EOF
    log_file chatterbox.log
    spawn ./target/debug/chatterbox --omemo-dir /tmp/foobar/
    # Wait for OMEMO bundle/device list to be published
    sleep 5
    send "\033"            ;# Send Esc key to exit the app
    expect eof
EOF
) || true

# Check that cb's bundle was published successfully
if ! grep "Bundle published successfully" chatterbox.log; then
    echo "cb's OMEMO bundle was not published!"
    cat chatterbox.log
    exit 1
fi

# 1. Run as ca to send a message to cb using expect
rm -f chatterbox.log
export XMPP_USERNAME="ca"
export XMPP_PASSWORD="+ng0APPS2TCL1rTeWZjXA1ULFz5ns34"
export RECIPIENT="cb@xmpp.server.org"
export TEST_MESSAGE="hello from ca to cb"

(
    timeout 30s expect <<EOF
    log_file chatterbox.log
    spawn ./target/debug/chatterbox
    expect "To:"           ;# Adjust this prompt to match your app
    send "$RECIPIENT\r"
    expect "Message:"      ;# Adjust this prompt to match your app
    send "$TEST_MESSAGE\r"
    sleep 2
    send "\033"            ;# Send Esc key to exit the app
    expect eof
EOF
) || true

grep "Failed to encrypt message" chatterbox.log && (cat chatterbox.log && exit 1)

grep "$TEST_MESSAGE" chatterbox.log || (cat chatterbox.log && exit 1)

# 4. Run as cb to receive the message from ca
rm -f chatterbox.log
export XMPP_USERNAME="cb"
export XMPP_PASSWORD="+ng0APPS2TCL1rTeWZjXA1ULFz5ns35"

(
    timeout 30s expect <<EOF
    log_file chatterbox.log
    spawn ./target/debug/chatterbox
    expect "To:"           ;# Adjust this prompt to match your app
    send "ca@xmpp.server.org\r"
    sleep 2
    send "\033"            ;# Send Esc key to exit the app
    expect eof
EOF
) || true

# 5. Check if the message was received
grep "$TEST_MESSAGE" chatterbox.log || (cat chatterbox.log && exit 1)

echo PASSED ✅ 