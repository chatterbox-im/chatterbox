#!/bin/bash
# =============================================================================
# SSL Certificate Generator for XMPP Server
# =============================================================================
#
# This script generates self-signed SSL certificates for the XMPP server
# These certificates will be used by the Nginx proxy for TLS connections
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
SSL_DIR="${SCRIPT_DIR}/nginx-config/ssl"

# Create SSL directory if it doesn't exist
mkdir -p "${SSL_DIR}"

echo -e "${BLUE}Generating self-signed SSL certificates for XMPP server...${NC}"

# Generate private key
echo -e "${YELLOW}Generating private key...${NC}"
openssl genrsa -out "${SSL_DIR}/xmpp.key" 2048

# Generate certificate signing request
echo -e "${YELLOW}Generating certificate signing request...${NC}"
openssl req -new -key "${SSL_DIR}/xmpp.key" -out "${SSL_DIR}/xmpp.csr" -subj "/CN=localhost/O=XMPP Test Server/C=US"

# Generate self-signed certificate
echo -e "${YELLOW}Generating self-signed certificate...${NC}"
openssl x509 -req -days 365 -in "${SSL_DIR}/xmpp.csr" -signkey "${SSL_DIR}/xmpp.key" -out "${SSL_DIR}/xmpp.crt"

# Add subject alternative name
echo -e "${YELLOW}Adding subject alternative name...${NC}"
cat > "${SSL_DIR}/san.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = xmpp-server
DNS.3 = prosody
EOF

# Create final certificate with SAN
openssl x509 -req -days 365 -in "${SSL_DIR}/xmpp.csr" -signkey "${SSL_DIR}/xmpp.key" -out "${SSL_DIR}/xmpp.crt" -extfile "${SSL_DIR}/san.cnf" -extensions v3_req

echo -e "${GREEN}SSL certificates generated successfully at:${NC}"
echo -e "  Private key: ${SSL_DIR}/xmpp.key"
echo -e "  Certificate: ${SSL_DIR}/xmpp.crt"

# Set appropriate permissions
chmod 600 "${SSL_DIR}/xmpp.key"
chmod 644 "${SSL_DIR}/xmpp.crt"

echo -e "${GREEN}Done!${NC}"