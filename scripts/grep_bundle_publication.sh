#!/bin/bash
set -ex
grep "Bundle published successfully" chatterbox.log || (cat chatterbox.log && return 1)
echo PASSED ✅
