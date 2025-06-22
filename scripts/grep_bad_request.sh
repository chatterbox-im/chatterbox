#!/bin/bash
set -ex

grep bad-request chatterbox.log || (cat chatterbox.log && exit 1)

echo "ALL CHECKS PASSED ✅"
