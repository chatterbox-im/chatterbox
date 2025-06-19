#!/bin/bash
set -ex
rm -f chatterbox.log
export XMPP_SERVER="xmpp.server.org"
export XMPP_USERNAME="ca"
export XMPP_PASSWORD="+ng0APPS2TCL1rTeWZjXA1ULFz5ns34"
timeout 20s ./target/debug/chatterbox || true
grep "Bundle published successfully" chatterbox.log || (cat chatterbox.log && return 1)
echo PASSED ✅
