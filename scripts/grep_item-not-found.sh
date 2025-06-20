#!/bin/bash
set -ex
rm -f chatterbox.log
timeout 20s ./target/debug/chatterbox || true
grep -v "item-not-found" chatterbox.log || (cat chatterbox.log && return 1)
echo PASSED ✅
