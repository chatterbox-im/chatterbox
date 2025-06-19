#!/bin/bash
set -ex
rm -f chatterbox.log
export XMPP_SERVER="xmpp.server.org"
export XMPP_USERNAME="ca"
export XMPP_PASSWORD="+ng0APPS2TCL1rTeWZjXA1ULFz5ns34"
timeout 20s ./target/debug/chatterbox || true

grep bad-request chatterbox.log || (cat chatterbox.log && exit 1)

echo "ALL CHECKS PASSED ✅"
