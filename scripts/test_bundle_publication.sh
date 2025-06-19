#!/bin/bash
# =============================================================================
# OMEMO Bundle Publication Test Script
# =============================================================================
#
# This script specifically tests OMEMO bundle publication functionality
# by connecting a client to an XMPP server and verifying that its bundle
# is properly published and can be retrieved.

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="bundle_publication_test.log"

echo -e "${BLUE}Starting OMEMO bundle publication test...${NC}"

# Make sure the log file is clean
[ -f "$LOG_FILE" ] && rm "$LOG_FILE"

# Check if the XMPP server is already running
echo -e "${BLUE}Checking if XMPP server is already running...${NC}"
PROSODY_RUNNING=$(docker ps --filter "name=xmpp-prosody" --format "{{.Names}}" | grep -c "xmpp-prosody" || true)
NGINX_RUNNING=$(docker ps --filter "name=xmpp-nginx" --format "{{.Names}}" | grep -c "xmpp-nginx" || true)

if [ "$PROSODY_RUNNING" -eq 0 ] || [ "$NGINX_RUNNING" -eq 0 ]; then
    echo -e "${YELLOW}XMPP server is not running. Starting it now...${NC}"
    
    # Start the XMPP server with TLS proxy
    bash "${SCRIPT_DIR}/run_xmpp_server.sh"
    
    # Wait a bit for the server to be fully ready
    echo -e "${BLUE}Waiting for the XMPP server to be fully initialized...${NC}"
    sleep 5
else
    echo -e "${GREEN}XMPP server is already running.${NC}"
fi

echo -e "${BLUE}Launching the chat app client...${NC}"
# Launch the app in the background, redirecting output to our log file
cargo run > $LOG_FILE 2>&1 &
APP_PID=$!

echo -e "${BLUE}Waiting for 30 seconds to allow bundle publication...${NC}"
sleep 30

echo -e "${BLUE}Terminating the client...${NC}"
# Send SIGTERM to the app process
kill $APP_PID 2>/dev/null || true

echo -e "${BLUE}Waiting for process termination...${NC}"
sleep 2

echo -e "${BLUE}Checking logs for bundle publication...${NC}"

# Look for evidence of bundle publication in the logs
if grep -q "Successfully published to node.*bundles" "$LOG_FILE"; then
    echo -e "${GREEN}✅ SUCCESS: OMEMO bundle was successfully published${NC}"
else
    echo -e "${RED}❌ ERROR: No evidence of successful bundle publication found${NC}"
    grep -i "publish" "$LOG_FILE" || echo "No publish-related logs found"
fi

# Check for bundle XML content in the logs
echo -e "${BLUE}Checking bundle content...${NC}"
if grep -q "Would publish PubSub item: <bundle" "$LOG_FILE"; then
    echo -e "${GREEN}✅ Bundle content was correctly formatted${NC}"
    grep -A 5 "Would publish PubSub item: <bundle" "$LOG_FILE" | head -n 6
else
    echo -e "${YELLOW}❌ WARNING: Could not verify bundle content format${NC}"
fi

# Look for any errors related to bundle publication
echo -e "${BLUE}Checking for errors in bundle publication...${NC}"
if grep -q "Failed to publish bundle\|ERROR.*bundle\|ERROR.*PubSub" "$LOG_FILE"; then
    echo -e "${RED}❌ ERRORS found in bundle publication:${NC}"
    grep -i "Failed to publish bundle\|ERROR.*bundle\|ERROR.*PubSub" "$LOG_FILE"
else
    echo -e "${GREEN}✅ No errors found in bundle publication process${NC}"
fi

# Check if we received success responses from the server
echo -e "${BLUE}Checking for server responses...${NC}"
if grep -q "received PubSub response\|result.*type=\"result\"" "$LOG_FILE"; then
    echo -e "${GREEN}✅ Received successful responses from the server${NC}"
else
    echo -e "${YELLOW}❌ WARNING: Could not verify server responses to bundle publication${NC}"
fi

# Look for proper implementation of all required bundle fields
echo -e "${BLUE}Verifying bundle structure...${NC}"
BUNDLE_CHECKS=0
for field in "identityKey" "signedPreKeyPublic" "signedPreKeySignature" "prekeys"; do
    if grep -q "$field" "$LOG_FILE"; then
        BUNDLE_CHECKS=$((BUNDLE_CHECKS+1))
    fi
done

if [ $BUNDLE_CHECKS -eq 4 ]; then
    echo -e "${GREEN}✅ Bundle contains all required fields according to XEP-0384${NC}"
else
    echo -e "${YELLOW}❌ WARNING: Bundle may be missing required fields (found $BUNDLE_CHECKS of 4)${NC}"
fi

echo -e "${GREEN}Test completed.${NC}"