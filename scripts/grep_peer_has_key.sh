#!/bin/bash
set -ex
rm -f chatterbox.log
export XMPP_SERVER="xmpp.server.org"
export XMPP_USERNAME="ca"
export XMPP_PASSWORD="+ng0APPS2TCL1rTeWZjXA1ULFz5ns34"
timeout 20s ./target/debug/chatterbox || true
grep "key rid" chatterbox.log
echo "✅ Peer has key"