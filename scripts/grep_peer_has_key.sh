#!/bin/bash
set -ex
rm -f chatterbox.log
timeout 20s ./target/debug/chatterbox || true
grep "key rid" chatterbox.log
echo "✅ Peer has key"