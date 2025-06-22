#!/bin/bash
set -ex
rm -f chatterbox.log

timeout 30s ./target/debug/chatterbox || true
grep "Bundle published successfully" chatterbox.log || (cat chatterbox.log && return 1)
echo PASSED ✅
