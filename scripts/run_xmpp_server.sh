#!/bin/bash
# =============================================================================
# Local XMPP Server Setup Script
# =============================================================================
#
# This script sets up a local XMPP server using Docker and creates test accounts
# based on the credentials defined in .github/test_credentials.json
#
# The script will:
# 1. Pull and run a Prosody XMPP server in Docker
# 2. Configure the server with the necessary modules and settings
# 3. Create user accounts based on the test credentials
# 4. Setup an Nginx proxy with TLS for secure connections
# 5. Expose the necessary ports for XMPP communication
#
# =============================================================================

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_CREDS="${SCRIPT_DIR}/.github/test_credentials.json"
PROSODY_CONFIG_DIR="${SCRIPT_DIR}/prosody-config"
NGINX_CONFIG_DIR="${SCRIPT_DIR}/nginx-config"
PROSODY_CONTAINER_NAME="xmpp-prosody"
NGINX_CONTAINER_NAME="xmpp-nginx"
DOCKER_NETWORK_NAME="xmpp-network"
PROSODY_DOMAIN="localhost"  # We'll use localhost instead of the original domain

# Check if docker is installed
check_docker() {
  echo -e "${BLUE}Checking if Docker is installed...${NC}"
  
  if ! command -v docker &> /dev/null; then
    echo -e "${RED}ERROR: Docker is not installed.${NC}"
    echo -e "${YELLOW}Please install Docker and try again.${NC}"
    exit 1
  fi
  
  echo -e "${GREEN}Docker is installed!${NC}"
}

# Check if jq is installed
check_jq() {
  echo -e "${BLUE}Checking if jq is installed...${NC}"
  
  if ! command -v jq &> /dev/null; then
    echo -e "${RED}ERROR: jq is not installed.${NC}"
    echo -e "${YELLOW}Please install jq and try again.${NC}"
    exit 1
  fi
  
  echo -e "${GREEN}jq is installed!${NC}"
}

# Check if test_credentials.json exists
check_test_credentials() {
  echo -e "${BLUE}Checking if test credentials file exists...${NC}"
  
  if [ ! -f "$TEST_CREDS" ]; then
    # Try looking for it in the script directory
    TEST_CREDS="${SCRIPT_DIR}/local_test_credentials.json"
    if [ ! -f "$TEST_CREDS" ]; then
      echo -e "${RED}ERROR: Test credentials file not found${NC}"
      exit 1
    fi
  fi
  
  echo -e "${GREEN}Test credentials found at $TEST_CREDS${NC}"
}

# Generate SSL certificates for Nginx
generate_certificates() {
  echo -e "${BLUE}Generating SSL certificates for XMPP server...${NC}"
  
  # Run the certificate generation script
  "${SCRIPT_DIR}/generate_certificates.sh"
}

# Setup Prosody configuration directory
setup_config_dir() {
  echo -e "${BLUE}Setting up Prosody configuration directory...${NC}"
  
  mkdir -p "${PROSODY_CONFIG_DIR}"
  
  # Create prosody.cfg.lua
  cat > "${PROSODY_CONFIG_DIR}/prosody.cfg.lua" << EOF
-- Prosody XMPP Server Configuration
-- For testing an OMEMO-compatible XMPP client

-- Server-wide settings
admins = {}
use_libevent = true
modules_enabled = {
    -- Generally required
    "roster"; -- Allow users to have a roster. Recommended ;)
    "saslauth"; -- Authentication for clients and servers. Recommended if you want to log in.
    "tls"; -- Add support for secure TLS on c2s/s2s connections
    "dialback"; -- s2s dialback support
    "disco"; -- Service discovery
    
    -- OMEMO-related modules
    "pubsub"; -- Publish/Subscribe for creating persistent OMEMO sessions
    "pep"; -- Personal Eventing Protocol (required for OMEMO)
    "carbons"; -- Message Carbons for multi-device support
    "mam"; -- Message Archive Management for offline messages
    
    -- Other useful modules
    "blocklist"; -- Allow users to block communications with other users
    "vcard4"; -- User profiles (stored in PEP)
    "vcard_legacy"; -- Legacy vCard support
    "private"; -- Private XML storage (for room bookmarks, etc.)
    "version"; -- Replies to server version requests
    "uptime"; -- Report how long server has been running
    "time"; -- Let others know the time here on this server
    "ping"; -- Replies to XMPP pings with pongs
    "register"; -- Allow users to register on this server using a client
    "posix"; -- POSIX functionality, sends server to background, enables syslog, etc.
}

-- Force clients to use encrypted connections
c2s_require_encryption = false  -- Set to false for internal connections with Nginx proxy

-- Various settings
certificates_dir = "/etc/prosody/certs"

-- For testing, use plain auth (no TLS required internally)
authentication = "internal_plain"

-- Basic HTTP server
http_ports = { 5280 }
http_interfaces = { "*" }

log = {
    info = "prosody.log"; -- Change 'info' to 'debug' for verbose logging
    error = "prosody.err";
    "*syslog"; -- Uncomment this for logging to syslog
}

-- Domain configuration (hostname, IPs, patterns, etc.)
hosts = { "${PROSODY_DOMAIN}" }

-- Set up the VirtualHost for the domain
VirtualHost "${PROSODY_DOMAIN}"
    -- Allow users to register accounts
    allow_registration = true
    
    -- Force the hostname to appear as localhost
    force_default_server = "${PROSODY_DOMAIN}"
    
    -- These modules are enabled only for this virtual host
    modules_enabled = {
        "ping"; -- Enable mod_ping
    }
    
    -- OMEMO
    default_archive_policy = "roster"  -- Archive only messages from users in your roster by default
    archive_expires_after = "1w"       -- Delete archived messages after 1 week
    
    -- MAM (Message Archive Management)
    mam_smart_enable = true            -- Enable MAM for non-anonymous users only
    mam_default = "roster"             -- Archive only messages from users in your roster by default
EOF

  echo -e "${GREEN}Prosody configuration created!${NC}"
}

# Create Docker network
create_docker_network() {
  echo -e "${BLUE}Creating Docker network...${NC}"
  
  # Check if network already exists
  if docker network ls | grep -q "${DOCKER_NETWORK_NAME}"; then
    echo -e "${YELLOW}Network ${DOCKER_NETWORK_NAME} already exists${NC}"
  else
    docker network create ${DOCKER_NETWORK_NAME}
    echo -e "${GREEN}Created Docker network: ${DOCKER_NETWORK_NAME}${NC}"
  fi
}

# Function to get client data
get_client_data() {
  local client_key=$1
  local username=$(jq -r ".${client_key}.username" "${TEST_CREDS}")
  local password=$(jq -r ".${client_key}.password" "${TEST_CREDS}")
  
  echo "${username}|${password}"
}

# Stop and remove existing containers if they exist
cleanup_existing_containers() {
  echo -e "${BLUE}Checking for existing containers...${NC}"
  
  # Check for Prosody container
  if docker ps -a --format '{{.Names}}' | grep -q "^${PROSODY_CONTAINER_NAME}$"; then
    echo -e "${YELLOW}Found existing container ${PROSODY_CONTAINER_NAME}. Stopping and removing...${NC}"
    docker stop ${PROSODY_CONTAINER_NAME} &>/dev/null || true
    docker rm ${PROSODY_CONTAINER_NAME} &>/dev/null || true
  fi
  
  # Check for Nginx container
  if docker ps -a --format '{{.Names}}' | grep -q "^${NGINX_CONTAINER_NAME}$"; then
    echo -e "${YELLOW}Found existing container ${NGINX_CONTAINER_NAME}. Stopping and removing...${NC}"
    docker stop ${NGINX_CONTAINER_NAME} &>/dev/null || true
    docker rm ${NGINX_CONTAINER_NAME} &>/dev/null || true
  fi
  
  echo -e "${GREEN}Cleanup complete.${NC}"
}

# Run Prosody container
run_prosody_container() {
  echo -e "${BLUE}Starting Prosody XMPP server...${NC}"
  
  docker run -d --name ${PROSODY_CONTAINER_NAME} \
    --network ${DOCKER_NETWORK_NAME} \
    -v "${PROSODY_CONFIG_DIR}/prosody.cfg.lua:/etc/prosody/prosody.cfg.lua" \
    -e XMPP_DOMAIN="${PROSODY_DOMAIN}" \
    prosody/prosody:latest
  
  # Wait for Prosody to start
  echo -e "${YELLOW}Waiting for Prosody to start...${NC}"
  sleep 5
  
  echo -e "${GREEN}Prosody XMPP server started!${NC}"
}

# Run Nginx proxy container
run_nginx_container() {
  echo -e "${BLUE}Starting Nginx TLS proxy...${NC}"
  
  docker run -d --name ${NGINX_CONTAINER_NAME} \
    --network ${DOCKER_NETWORK_NAME} \
    -p 5223:5223 \
    -p 5270:5270 \
    -p 5281:5281 \
    -v "${NGINX_CONFIG_DIR}/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "${NGINX_CONFIG_DIR}/ssl:/etc/nginx/ssl:ro" \
    nginx:latest
  
  # Wait for Nginx to start
  echo -e "${YELLOW}Waiting for Nginx to start...${NC}"
  sleep 3
  
  echo -e "${GREEN}Nginx TLS proxy started!${NC}"
}

# Create test accounts
create_test_accounts() {
  echo -e "${BLUE}Creating test accounts...${NC}"
  
  # Get client data
  clientA_data=$(get_client_data "clientA")
  clientB_data=$(get_client_data "clientB")
  
  # Extract usernames and passwords
  clientA_username=$(echo "${clientA_data}" | cut -d'|' -f1)
  clientA_password=$(echo "${clientA_data}" | cut -d'|' -f2)
  clientB_username=$(echo "${clientB_data}" | cut -d'|' -f1)
  clientB_password=$(echo "${clientB_data}" | cut -d'|' -f2)
  
  # Create account for Client A
  echo -e "${YELLOW}Creating account for ${clientA_username}...${NC}"
  docker exec ${PROSODY_CONTAINER_NAME} prosodyctl register ${clientA_username} ${PROSODY_DOMAIN} "${clientA_password}"
  
  # Create account for Client B
  echo -e "${YELLOW}Creating account for ${clientB_username}...${NC}"
  docker exec ${PROSODY_CONTAINER_NAME} prosodyctl register ${clientB_username} ${PROSODY_DOMAIN} "${clientB_password}"
  
  echo -e "${GREEN}Test accounts created!${NC}"
}

# Create an updated credentials file for the local server
create_local_credentials() {
  echo -e "${BLUE}Creating local credentials file...${NC}"
  
  # Get client data
  clientA_data=$(get_client_data "clientA")
  clientB_data=$(get_client_data "clientB")
  
  # Extract usernames and passwords
  clientA_username=$(echo "${clientA_data}" | cut -d'|' -f1)
  clientA_password=$(echo "${clientA_data}" | cut -d'|' -f2)
  clientB_username=$(echo "${clientB_data}" | cut -d'|' -f1)
  clientB_password=$(echo "${clientB_data}" | cut -d'|' -f2)
  
  # Create a local credentials file with the local server
  cat > "${SCRIPT_DIR}/local_test_credentials.json" << EOF
{
  "clientA": {
    "server": "${PROSODY_DOMAIN}",
    "username": "${clientA_username}",
    "password": "${clientA_password}",
    "jid": "${clientA_username}@${PROSODY_DOMAIN}"
  },
  "clientB": {
    "server": "${PROSODY_DOMAIN}",
    "username": "${clientB_username}",
    "password": "${clientB_password}",
    "jid": "${clientB_username}@${PROSODY_DOMAIN}"
  }
}
EOF

  echo -e "${GREEN}Local credentials file created at ${SCRIPT_DIR}/local_test_credentials.json${NC}"
}

# Display server information
display_server_info() {
  echo -e "${BLUE}=======================================================${NC}"
  echo -e "${GREEN}XMPP Server with TLS Proxy is running!${NC}"
  echo -e "${BLUE}=======================================================${NC}"
  echo -e "${YELLOW}Server Information:${NC}"
  echo -e "  Domain: ${PROSODY_DOMAIN}"
  echo -e "${YELLOW}Secure connection ports (TLS enabled):${NC}"
  echo -e "  Client Port: 5223 (TLS)"
  echo -e "  Server Port: 5270 (TLS)"
  echo -e "  HTTP/WebSocket Port: 5281 (HTTPS)"
  echo -e "${YELLOW}Created Accounts:${NC}"
  
  # Get client data
  clientA_data=$(get_client_data "clientA")
  clientB_data=$(get_client_data "clientB")
  
  # Extract usernames
  clientA_username=$(echo "${clientA_data}" | cut -d'|' -f1)
  clientB_username=$(echo "${clientB_data}" | cut -d'|' -f1)
  
  echo -e "  JID: ${clientA_username}@${PROSODY_DOMAIN}"
  echo -e "  JID: ${clientB_username}@${PROSODY_DOMAIN}"
  echo -e "${YELLOW}Connection Information for clients:${NC}"
  echo -e "  For TLS connections, set port to 5223 and enable TLS"
  echo -e "  For HTTPS/WebSocket connections, use https://localhost:5281/"
  echo -e "${BLUE}=======================================================${NC}"
  echo -e "${YELLOW}To stop the servers, run:${NC}"
  echo -e "  docker stop ${NGINX_CONTAINER_NAME} ${PROSODY_CONTAINER_NAME}"
  echo -e "${YELLOW}To start the servers again, run:${NC}"
  echo -e "  docker start ${PROSODY_CONTAINER_NAME} ${NGINX_CONTAINER_NAME}"
  echo -e "${BLUE}=======================================================${NC}"
}

# Check server reachability
check_server_reachability() {
  echo -e "${BLUE}Checking if XMPP server is reachable...${NC}"

  # Try to connect to the XMPP server port
  if nc -zv localhost 5223 &>/dev/null; then
    echo -e "${GREEN}✓ XMPP server is reachable on secure port 5223!${NC}"
  else
    echo -e "${RED}✗ Cannot connect to XMPP server on secure port 5223.${NC}"
    echo -e "${YELLOW}There might be an issue with the server configuration.${NC}"
  fi

  # Try to connect to the HTTP/WebSocket port
  if nc -zv localhost 5281 &>/dev/null; then
    echo -e "${GREEN}✓ XMPP server HTTP/WebSocket interface is reachable on port 5281!${NC}"
  else
    echo -e "${RED}✗ Cannot connect to XMPP server HTTP/WebSocket interface on port 5281.${NC}"
    echo -e "${YELLOW}There might be an issue with the Nginx configuration.${NC}"
  fi
}

# Main function
main() {
  echo -e "${BLUE}Setting up local XMPP server with TLS proxy for testing...${NC}"
  
  check_docker
  check_jq
  check_test_credentials
  setup_config_dir
  generate_certificates
  cleanup_existing_containers
  create_docker_network
  run_prosody_container
  run_nginx_container
  create_test_accounts
  create_local_credentials
  display_server_info
  check_server_reachability
  
  echo -e "${GREEN}Setup complete!${NC}"
}

# Run the script
main