#!/bin/bash
set -ex
rm -f chatterbox.log
timeout 20s ./target/debug/chatterbox || true

grep bad-request chatterbox.log || (cat chatterbox.log && exit 1)

echo "ALL CHECKS PASSED ✅"
