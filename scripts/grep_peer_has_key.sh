#!/bin/bash
set -ex
grep "key rid" chatterbox.log
echo "✅ Peer has key"
