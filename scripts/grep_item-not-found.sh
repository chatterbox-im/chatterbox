#!/bin/bash
set -ex
grep -v "item-not-found" chatterbox.log || (cat chatterbox.log && return 1)
echo PASSED ✅
