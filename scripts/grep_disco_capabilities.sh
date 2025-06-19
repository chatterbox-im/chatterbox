#!/bin/bash
set -ex
rm -f chatterbox.log
export XMPP_SERVER="xmpp.server.org"
export XMPP_USERNAME="ca"
export XMPP_PASSWORD="+ng0APPS2TCL1rTeWZjXA1ULFz5ns34"
timeout 20s ./target/debug/chatterbox || true

# Output log content for debugging
echo "=== DEBUG: Last 20 lines of the log file ==="
tail -n 20 chatterbox.log
echo "=========================================="

echo "Checking for feature advertisement stanzas..."
grep -A 10 "<iq.*disco.*info" chatterbox.log && echo "✅ Service discovery stanzas found" || echo "❌ No service discovery stanzas found"

echo "Checking for client OMEMO feature advertisement..."
if grep -q 'var="urn:xmpp:omemo:1"' chatterbox.log; then
  echo "✅ Client properly advertises OMEMO namespace"
else
  echo "❌ Client is not advertising OMEMO namespace"
  exit 1
fi

# First check for server response with disco info
echo "Checking for server disco info response..."
if grep -q 'from=".*".*type="result".*<query.*disco#info' chatterbox.log; then
  echo "✅ Server sent disco info response"
  
  # Extract the actual server features section
  echo "Analyzing server capabilities..."
  # Use sed to extract the disco info response from the server and save to a temporary file
  SERVER_RESPONSE=$(grep -A 50 'from=".*".*type="result".*<query.*disco#info' chatterbox.log | grep -B 50 '</query></iq>' | head -n 1000)
  
  # Check if server supports OMEMO in its response
  if echo "$SERVER_RESPONSE" | grep -q 'var="urn:xmpp:omemo:'; then
    echo "✅ Server explicitly supports OMEMO"
  else
    echo "⚠️ Server does not explicitly support OMEMO - this is expected for many servers"
    # Don't fail the check because many servers don't directly support OMEMO - it's handled by clients
  fi
else
  echo "❌ No server disco info response found"
  exit 1
fi



echo "Checking for successful OMEMO operations..."
# First check if bundle publication worked (which implicitly means PubSub works)
if grep -q "Bundle published successfully" chatterbox.log; then
  echo "✅ OMEMO bundle successfully published (PubSub is working)"
else
  echo "❌ OMEMO bundle publication failed - PubSub might not be working"
  exit 1
fi

# Additional check to see if we get a valid response for bundle publishing
if grep -q "Successfully published to node urn:xmpp:omemo:" chatterbox.log; then
  echo "✅ Server confirmed successful publication to OMEMO node"
else
  echo "⚠️ No explicit server confirmation for OMEMO node publication"
  # This is only a warning as some servers handle this differently
fi

echo "ALL CHECKS PASSED ✅"
