timeout 20s ./target/debug/chatterbox || true
grep ERROR chatterbox.log
