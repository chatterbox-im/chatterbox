#!/bin/bash

# This script specifically tests message carbons functionality (XEP-0280) 
# by having two clients logged into the same account and sending messages
# to a third client, then checking if the messages are properly carbon-copied.

set -e # Exit immediately if a command exits with a non-zero status.
set -u # Treat unset variables as an error when substituting.
# set -x # Print commands and their arguments as they are executed. Useful for debugging.

# --- Configuration ---
# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "${SCRIPT_DIR}/.." &> /dev/null && pwd )"
WORKING_DIR="$(pwd)" # Save the original working directory
CREDENTIALS_FILE="${PROJECT_ROOT}/.github/test_credentials.json"
TMUX_SESSION="sermo-carbons-test"
SCRIPT_PANE=0 # Pane where test logic runs
CLIENT_A1_PANE=1 # Pane for Client A1 (first instance of account A)
CLIENT_A2_PANE=2 # Pane for Client A2 (second instance of account A)
CLIENT_B_PANE=3 # Pane for Client B (different account)
SCRIPT_LOG_FILE="${PROJECT_ROOT}/carbons_script_output.log"

# --- Helper Functions ---

log() {
    # Log messages will appear in the terminal where this script runs
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [Carbons Test] $1" | tee -a "$SCRIPT_LOG_FILE"
}

cleanup() {
    # Ensure TMUX_CMD is available
    local tmux_executable="${TMUX_CMD:-tmux}"
    log "Cleaning up carbon test resources..."

    # --- Copy Log Files ---
    for client in "A1" "A2" "B"; do
        local dir_var="CLIENT_${client}_OMEMO_DIR"
        local dir="${!dir_var:-}"
        
        if [ -n "$dir" ] && [ -d "$dir" ]; then
            log "Copying logs from Client $client: $dir"
            shopt -s nullglob
            for logfile in "$dir"/*.log; do
                if [ -f "$logfile" ]; then
                    filename=$(basename "$logfile")
                    destination_name="client_${client}_$filename"
                    # Copy to both project root and original working directory if different
                    log "  Copying: $logfile -> ${PROJECT_ROOT}/$destination_name"
                    cp -p "$logfile" "${PROJECT_ROOT}/$destination_name"
                    if [ "${WORKING_DIR}" != "${PROJECT_ROOT}" ]; then
                        log "  Also copying to original working directory: ${WORKING_DIR}/$destination_name"
                        cp -p "$logfile" "${WORKING_DIR}/$destination_name"
                    fi
                fi
            done
            shopt -u nullglob
            log "Removing dir: $dir"
            rm -rf "$dir"
        fi
    done

    # Kill the tmux session
    if "$tmux_executable" has-session -t "$TMUX_SESSION" 2>/dev/null; then
        log "Killing tmux session $TMUX_SESSION"
        "$tmux_executable" kill-session -t "$TMUX_SESSION" || log "Warning: Failed to kill tmux session"
    fi

    # Return to the original directory where the script was called from
    cd "${WORKING_DIR}"
    log "Returned to original working directory: $(pwd)"

    log "Cleanup finished."
}

run_carbons_test() {
    log "Starting message carbons test sequence..."
    
    # 6. Launch Clients
    # Action delay constants
    INITIAL_WAIT=20  # Initial wait for startup
    ACTION_DELAY=3   # Delay between actions
    KEY_DELAY=0.1    # Delay between keypresses
    OMEMO_WAIT=30    # Wait for OMEMO setup
    CARBON_DELAY=6   # Delay for carbon synchronization (2 * ACTION_DELAY)
    VERIFY_DELAY=9   # Delay for visual verification (3 * ACTION_DELAY)

    # Define targets for each pane
    SCRIPT_TARGET="$TMUX_SESSION:0.$SCRIPT_PANE"
    CLIENT_A1_TARGET="$TMUX_SESSION:0.$CLIENT_A1_PANE"
    CLIENT_A2_TARGET="$TMUX_SESSION:0.$CLIENT_A2_PANE"
    CLIENT_B_TARGET="$TMUX_SESSION:0.$CLIENT_B_PANE"

    # Launch Client A1 (first instance of user A)
    log "Launching Client A1 (first instance of user A)"
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" "clear" Enter
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" "export RUST_LOG=debug" Enter # Set to debug to capture more info about carbons
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" "export XMPP_SERVER='$CLIENT_A_SERVER'" Enter
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" "export XMPP_USERNAME='$CLIENT_A_USER'" Enter
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" "export XMPP_PASSWORD='$CLIENT_A_PASS'" Enter
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" "export XMPP_RESOURCE='device1'" Enter  # Use env var instead of command line arg
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" "target/debug/chatterbox --omemo-dir '$CLIENT_A1_OMEMO_DIR'" Enter

    # Launch Client A2 (second instance of user A)
    log "Launching Client A2 (second instance of user A)"
    "$TMUX_CMD" send-keys -t "$CLIENT_A2_TARGET" "clear" Enter
    "$TMUX_CMD" send-keys -t "$CLIENT_A2_TARGET" "export RUST_LOG=debug" Enter
    "$TMUX_CMD" send-keys -t "$CLIENT_A2_TARGET" "export XMPP_SERVER='$CLIENT_A_SERVER'" Enter
    "$TMUX_CMD" send-keys -t "$CLIENT_A2_TARGET" "export XMPP_USERNAME='$CLIENT_A_USER'" Enter
    "$TMUX_CMD" send-keys -t "$CLIENT_A2_TARGET" "export XMPP_PASSWORD='$CLIENT_A_PASS'" Enter
    "$TMUX_CMD" send-keys -t "$CLIENT_A2_TARGET" "export XMPP_RESOURCE='device2'" Enter  # Use env var instead of command line arg
    "$TMUX_CMD" send-keys -t "$CLIENT_A2_TARGET" "target/debug/chatterbox --omemo-dir '$CLIENT_A2_OMEMO_DIR'" Enter

    # Launch Client B (user B)
    log "Launching Client B (user B)"
    "$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "clear" Enter
    "$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "export RUST_LOG=debug" Enter
    "$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "export XMPP_SERVER='$CLIENT_B_SERVER'" Enter
    "$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "export XMPP_USERNAME='$CLIENT_B_USER'" Enter
    "$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "export XMPP_PASSWORD='$CLIENT_B_PASS'" Enter
    "$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "target/debug/chatterbox --omemo-dir '$CLIENT_B_OMEMO_DIR'" Enter

    # 7. Wait for clients to initialize
    log "Waiting $INITIAL_WAIT seconds for clients to initialize..."
    sleep $INITIAL_WAIT

    # 8. Enable message carbons on both A1 and A2 (same account)
    log "Client A1: Enabling message carbons"
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" C-m # Ctrl+M to enable carbons
    sleep $ACTION_DELAY

    log "Client A2: Enabling message carbons"
    "$TMUX_CMD" send-keys -t "$CLIENT_A2_TARGET" C-m # Ctrl+M to enable carbons
    sleep $ACTION_DELAY

    # 9. Client A1: Add contact B
    log "Client A1: Adding contact $CLIENT_B_JID"
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" C-a # Ctrl+A to open Add Contact dialog
    sleep $ACTION_DELAY
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" "$CLIENT_B_JID"
    sleep $KEY_DELAY
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" Enter
    sleep $ACTION_DELAY

    # 10. Client B: Add contact A
    log "Client B: Adding contact $CLIENT_A_JID"
    "$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" C-a # Ctrl+A to open Add Contact dialog
    sleep $ACTION_DELAY
    "$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "$CLIENT_A_JID"
    sleep $KEY_DELAY
    "$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" Enter
    sleep $ACTION_DELAY

    log "Waiting $OMEMO_WAIT seconds for OMEMO setup (device list exchange)..."
    sleep $OMEMO_WAIT

    # 11. Establish trust between A1 and B
    log "Client A1: Trusting Client B's devices"
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" C-t # Ctrl+T to toggle trust
    sleep $ACTION_DELAY

    log "Client B: Trusting Client A's devices"
    "$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" C-t # Ctrl+T to toggle trust
    sleep $ACTION_DELAY

    # 12. Send test message from Client A1 to Client B for carbon testing
    log "Client A1: Sending message to Client B (this should be carbon-copied to A2)"
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" "Hello from Client A1! This message should be carbon-copied to A2."
    sleep $KEY_DELAY
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" Enter
    sleep $CARBON_DELAY

    # 13. Check if Client A2 received the carbon copy
    log "Checking Client A2 for carbon copy of the message (visual verification)"
    sleep $VERIFY_DELAY

    # 14. Have Client B reply to verify bidirectional communication
    log "Client B: Replying to Client A's message"
    "$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "Hello from Client B! Replying to your message."
    sleep $KEY_DELAY
    "$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" Enter
    sleep $CARBON_DELAY

    # 15. Check if the reply was received by both clients
    log "Checking both Client A1 and A2 to see if they received Client B's reply"
    sleep $VERIFY_DELAY

    # 16. Test with OMEMO encryption
    log "Client A1: Sending encrypted message to Client B"
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" "This is an encrypted message. It should also be carbon-copied to A2."
    sleep $KEY_DELAY
    "$TMUX_CMD" send-keys -t "$CLIENT_A1_TARGET" Enter
    sleep $VERIFY_DELAY

    log "End of test. Pausing for 20 seconds to observe results..."
    sleep 20

    log "Test complete."
}

# Ensure cleanup runs on exit
trap cleanup EXIT ERR INT TERM

# --- Main Script ---

log "Starting message carbons test script..."
log "Project root: ${PROJECT_ROOT}"
log "Working directory: ${WORKING_DIR}"

# 1. Check prerequisites
log "Checking prerequisites..."

# Find tmux path
if ! TMUX_CMD=$(which tmux); then
    log "Error: tmux executable not found in PATH. Please install tmux."
    exit 1
fi
log "Using tmux at: $TMUX_CMD"

if ! command -v jq &> /dev/null; then
    log "Error: jq could not be found. Please install jq."
    exit 1
fi
if [ ! -f "$CREDENTIALS_FILE" ]; then
    log "Error: Credentials file not found at $CREDENTIALS_FILE"
    exit 1
fi
if [ ! -f "${PROJECT_ROOT}/Cargo.toml" ]; then
    log "Error: Cargo.toml not found in project root: ${PROJECT_ROOT}"
    exit 1
fi
log "Prerequisites met."

# Change to project root for execution
cd "${PROJECT_ROOT}"
log "Changed working directory to project root: $(pwd)"

# 2. Parse Credentials
log "Parsing credentials from $CREDENTIALS_FILE..."
# Parse user A's credentials (will be used for both Client A1 and A2)
CLIENT_A_SERVER=$(jq -r '.clientA.server // ""' "$CREDENTIALS_FILE")
CLIENT_A_USER=$(jq -r '.clientA.username // ""' "$CREDENTIALS_FILE")
CLIENT_A_PASS=$(jq -r '.clientA.password // ""' "$CREDENTIALS_FILE")
CLIENT_A_JID=$(jq -r '.clientA.jid // ""' "$CREDENTIALS_FILE")

# Parse user B's credentials
CLIENT_B_SERVER=$(jq -r '.clientB.server // ""' "$CREDENTIALS_FILE")
CLIENT_B_USER=$(jq -r '.clientB.username // ""' "$CREDENTIALS_FILE")
CLIENT_B_PASS=$(jq -r '.clientB.password // ""' "$CREDENTIALS_FILE")
CLIENT_B_JID=$(jq -r '.clientB.jid // ""' "$CREDENTIALS_FILE")

# Check if essential variables were successfully parsed
if [ -z "$CLIENT_A_SERVER" ] || [ -z "$CLIENT_A_USER" ] || [ -z "$CLIENT_A_PASS" ] || [ -z "$CLIENT_A_JID" ]; then
    log "Error: Could not parse all required credentials for Client A from $CREDENTIALS_FILE."
    exit 1
fi
if [ -z "$CLIENT_B_SERVER" ] || [ -z "$CLIENT_B_USER" ] || [ -z "$CLIENT_B_PASS" ] || [ -z "$CLIENT_B_JID" ]; then
    log "Error: Could not parse all required credentials for Client B from $CREDENTIALS_FILE."
    exit 1
fi
log "Credentials parsed successfully."

# 3. Create Temporary Directories (separate dirs for each client)
log "Creating temporary OMEMO directories..."
export CLIENT_A1_OMEMO_DIR=$(mktemp -d -t sermo-client-a1-XXXXXX)
export CLIENT_A2_OMEMO_DIR=$(mktemp -d -t sermo-client-a2-XXXXXX)
export CLIENT_B_OMEMO_DIR=$(mktemp -d -t sermo-client-b-XXXXXX)
log "Client A1 OMEMO dir: $CLIENT_A1_OMEMO_DIR"
log "Client A2 OMEMO dir: $CLIENT_A2_OMEMO_DIR"
log "Client B OMEMO dir: $CLIENT_B_OMEMO_DIR"

# 4. Build the App
log "Building the application with cargo..."
cargo build || {
    log "Error: Failed to build the application"
    exit 1
}
log "Build complete."

# 5. Setup Tmux
log "Setting up tmux session with 4 panes..."
"$TMUX_CMD" kill-session -t "$TMUX_SESSION" 2>/dev/null || true # Kill if exists

# Create the session with 4 panes
"$TMUX_CMD" new-session -d -s "$TMUX_SESSION" -n "Carbons Test" bash
"$TMUX_CMD" split-window -v -t "$TMUX_SESSION:0.$SCRIPT_PANE" # Split horizontally for A1
"$TMUX_CMD" split-window -h -t "$TMUX_SESSION:0.$CLIENT_A1_PANE" # Split A1 pane for A2
"$TMUX_CMD" split-window -h -t "$TMUX_SESSION:0.$CLIENT_A2_PANE" # Split A2 pane for B

log "Tmux session created with panes for script, Client A1, Client A2, and Client B"

# Setup script pane with logs
"$TMUX_CMD" send-keys -t "$TMUX_SESSION:0.$SCRIPT_PANE" "clear" Enter
"$TMUX_CMD" send-keys -t "$TMUX_SESSION:0.$SCRIPT_PANE" "echo 'Carbons Test Script Log - Running test in other panes'" Enter
"$TMUX_CMD" send-keys -t "$TMUX_SESSION:0.$SCRIPT_PANE" "echo 'Started at: $(date)'" Enter
"$TMUX_CMD" send-keys -t "$TMUX_SESSION:0.$SCRIPT_PANE" "echo 'Pane Layout: [A1|A2|B] over [Script Log]'" Enter
"$TMUX_CMD" send-keys -t "$TMUX_SESSION:0.$SCRIPT_PANE" "echo 'Log file: $SCRIPT_LOG_FILE'" Enter
"$TMUX_CMD" send-keys -t "$TMUX_SESSION:0.$SCRIPT_PANE" "echo 'Test will run automatically - you can observe in real-time'" Enter
"$TMUX_CMD" send-keys -t "$TMUX_SESSION:0.$SCRIPT_PANE" "echo ''" Enter
"$TMUX_CMD" send-keys -t "$TMUX_SESSION:0.$SCRIPT_PANE" "tail -f $SCRIPT_LOG_FILE" Enter

# Run the test in background to allow attaching to the session
(run_carbons_test) &

# Attach to the session to see the test in real-time
log "Attaching to tmux session to view test in real-time..."
"$TMUX_CMD" attach-session -t "$TMUX_SESSION"

log "Detached from session. Test complete."
exit 0