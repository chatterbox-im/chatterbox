#!/bin/bash

# This script contains the core logic for the E2E test.
# It expects to be run inside the first pane (Pane 0) of a tmux session.
# It expects TMUX_SESSION, CLIENT_A_PANE, CLIENT_B_PANE, and TMUX_CMD env vars to be set.

set -e # Exit immediately if a command exits with a non-zero status.
set -u # Treat unset variables as an error when substituting.
# set -x # Print commands and their arguments as they are executed. Useful for debugging.

# --- Configuration (from environment) ---
CREDENTIALS_FILE=".github/test_credentials.json"
# TMUX_SESSION, CLIENT_A_PANE, CLIENT_B_PANE, TMUX_CMD should be inherited

# --- Helper Functions ---

log() {
    # Log messages will appear in the pane where this script runs (Pane 0)
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

cleanup() {
    # Ensure TMUX_CMD is available, default to 'tmux' if somehow not set (should be passed by wrapper)
    local tmux_executable="${TMUX_CMD:-tmux}"
    log "Cleaning up E2E test resources (using $tmux_executable)..."
    log "Current directory in cleanup: $(pwd)" # Add pwd log

    # --- Client A Log Copying (DO THIS *BEFORE* KILLING SESSION) --- 
    local client_a_dir="${CLIENT_A_OMEMO_DIR:-}" # Use local var for safety
    log "Checking Client A OMEMO dir: '$client_a_dir'"
    if [ -n "$client_a_dir" ] && [ -d "$client_a_dir" ]; then
        log "Attempting to copy log files from Client A OMEMO dir: $client_a_dir"
        found_logs_a=false
        shopt -s nullglob # Prevent loop from running if no *.log files exist
        log "Looking for files matching: $client_a_dir/*.log"
        for logfile in "$client_a_dir"/*.log; do
            if [ -f "$logfile" ]; then # Ensure it is a file
                filename=$(basename "$logfile")
                destination_name="client_a_$filename"
                log "  Found log file: '$logfile'"
                log "  Executing: cp -p \"$logfile\" \"./$destination_name\""
                cp -p "$logfile" "./$destination_name"
                if [ $? -ne 0 ]; then
                    log "  ERROR: Failed to copy '$logfile' to './$destination_name'"
                fi
                found_logs_a=true
            else 
                log "  Skipping non-file entry: $logfile"
            fi
        done
        shopt -u nullglob # Turn off nullglob
        if ! $found_logs_a; then
             log "No .log files found for Client A in $client_a_dir."
        fi
        log "Finished copying for Client A. Removing dir: $client_a_dir"
        rm -rf "$client_a_dir"
    else
        log "Client A OMEMO dir not set or not found: '$client_a_dir'"
    fi

    # --- Client B Log Copying (DO THIS *BEFORE* KILLING SESSION) --- 
    local client_b_dir="${CLIENT_B_OMEMO_DIR:-}" # Use local var for safety
    log "Checking Client B OMEMO dir: '$client_b_dir'"
    if [ -n "$client_b_dir" ] && [ -d "$client_b_dir" ]; then
        log "Attempting to copy log files from Client B OMEMO dir: $client_b_dir"
        found_logs_b=false
        shopt -s nullglob # Prevent loop from running if no *.log files exist
        log "Looking for files matching: $client_b_dir/*.log"
        for logfile in "$client_b_dir"/*.log; do
            if [ -f "$logfile" ]; then # Ensure it is a file
                filename=$(basename "$logfile")
                destination_name="client_b_$filename"
                log "  Found log file: '$logfile'"
                log "  Executing: cp -p \"$logfile\" \"./$destination_name\""
                cp -p "$logfile" "./$destination_name"
                if [ $? -ne 0 ]; then
                    log "  ERROR: Failed to copy '$logfile' to './$destination_name'"
                fi
                found_logs_b=true
            else
                log "  Skipping non-file entry: $logfile"
            fi
        done
        shopt -u nullglob # Turn off nullglob
        if ! $found_logs_b; then
             log "No .log files found for Client B in $client_b_dir."
        fi
        log "Finished copying for Client B. Removing dir: $client_b_dir"
        rm -rf "$client_b_dir"
    else
        log "Client B OMEMO dir not set or not found: '$client_b_dir'"
    fi

    # Kill the entire tmux session (DO THIS *LAST*) 
    if "$tmux_executable" has-session -t "$TMUX_SESSION" 2>/dev/null; then
        log "Killing tmux session $TMUX_SESSION"
        # Use kill-session which should terminate all processes and trigger traps if needed
        "$tmux_executable" kill-session -t "$TMUX_SESSION" || log "Warning: Failed to kill tmux session $TMUX_SESSION"
    else
        log "Tmux session $TMUX_SESSION already gone."
    fi

    log "Cleanup finished."
    # Note: The trap will exit the script after this function completes.
}

# Ensure cleanup runs on exit or error for THIS script
trap cleanup EXIT ERR INT TERM

# --- Main Logic ---

log "Starting E2E test logic inside tmux pane..."

# Check required environment variables
if [ -z "${TMUX_SESSION:-}" ]; then log "Error: TMUX_SESSION environment variable not set."; exit 1; fi
if [ -z "${CLIENT_A_PANE:-}" ]; then log "Error: CLIENT_A_PANE environment variable not set."; exit 1; fi
if [ -z "${CLIENT_B_PANE:-}" ]; then log "Error: CLIENT_B_PANE environment variable not set."; exit 1; fi
if [ -z "${TMUX_CMD:-}" ]; then 
    log "Error: TMUX_CMD environment variable not set (should be passed by wrapper script)."
    # Fallback to trying 'tmux' but this might fail if there's an alias
    TMUX_CMD="tmux"
    log "Warning: Falling back to using '$TMUX_CMD'. This might fail if it's an alias."
    # Optionally exit here if TMUX_CMD is strictly required: exit 1
fi
log "Using tmux command: $TMUX_CMD"

# Define pane targets using environment variables
CLIENT_A_TARGET="$TMUX_SESSION:0.$CLIENT_A_PANE" # e.g., sermo-e2e-test:0.1
CLIENT_B_TARGET="$TMUX_SESSION:0.$CLIENT_B_PANE" # e.g., sermo-e2e-test:0.2
log "Targeting Client A Pane: $CLIENT_A_TARGET"
log "Targeting Client B Pane: $CLIENT_B_TARGET"

# 1. Check remaining prerequisites (file existence)
if [ ! -f "$CREDENTIALS_FILE" ]; then
    log "Error: Credentials file not found at $CREDENTIALS_FILE"
    exit 1
fi
if [ ! -f "Cargo.toml" ]; then
    log "Error: Cargo.toml not found. Run this script from the project root."
    exit 1
fi

# 2. Parse Credentials
log "Parsing credentials from $CREDENTIALS_FILE..."
# Add default empty values to prevent unbound variable errors if jq fails or keys are missing
CLIENT_A_SERVER=$(jq -r '.clientA.server // ""' "$CREDENTIALS_FILE")
CLIENT_A_USER=$(jq -r '.clientA.username // ""' "$CREDENTIALS_FILE")
CLIENT_A_PASS=$(jq -r '.clientA.password // ""' "$CREDENTIALS_FILE")
CLIENT_A_JID=$(jq -r '.clientA.jid // ""' "$CREDENTIALS_FILE")

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

# 3. Create Temporary Directories
log "Creating temporary OMEMO directories..."
# Use mktemp under /tmp for broader compatibility and security
# Make CLIENT_A_OMEMO_DIR and CLIENT_B_OMEMO_DIR global so cleanup can access them
export CLIENT_A_OMEMO_DIR=$(mktemp -d -t sermo-client-a-XXXXXX)
export CLIENT_B_OMEMO_DIR=$(mktemp -d -t sermo-client-b-XXXXXX)
log "Client A OMEMO dir: $CLIENT_A_OMEMO_DIR"
log "Client B OMEMO dir: $CLIENT_B_OMEMO_DIR"

# 4. Build the App (optional here, could be done by wrapper)
log "Building the application with cargo..."
cargo build
log "Build complete."

# 5. Launch Clients (Tmux setup is handled by the wrapper script)
log "Launching Client A in pane $CLIENT_A_TARGET"
# Clear pane and run client A
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" C-c Enter # Send Ctrl+C just in case
sleep 0.2 # Short delay after Ctrl+C
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" "clear" Enter
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" "export RUST_LOG=info" Enter # Use info level unless debugging needed
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" "export XMPP_SERVER='$CLIENT_A_SERVER'" Enter
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" "export XMPP_USERNAME='$CLIENT_A_USER'" Enter
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" "export XMPP_PASSWORD='$CLIENT_A_PASS'" Enter
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" "target/debug/chatterbox --omemo-dir '$CLIENT_A_OMEMO_DIR'" Enter

log "Launching Client B in pane $CLIENT_B_TARGET"
# Clear pane and run client B
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" C-c Enter # Send Ctrl+C just in case
sleep 0.2 # Short delay after Ctrl+C
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "clear" Enter
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "export RUST_LOG=info" Enter
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "export XMPP_SERVER='$CLIENT_B_SERVER'" Enter
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "export XMPP_USERNAME='$CLIENT_B_USER'" Enter
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "export XMPP_PASSWORD='$CLIENT_B_PASS'" Enter
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "target/debug/chatterbox --omemo-dir '$CLIENT_B_OMEMO_DIR'" Enter

# 6. Automate Interactions
# Add delays to allow applications to start and process commands
INITIAL_WAIT=20 # Increased wait time for connection and OMEMO init
ACTION_DELAY=3  # Delay between actions
KEY_DELAY=0.1   # Short delay between key presses if needed
OMEMO_WAIT=30   # Increased wait time after adding contacts for OMEMO setup
TRUST_DELAY=2   # Wait after toggling trust

log "Waiting $INITIAL_WAIT seconds for clients to fully initialize OMEMO..."
sleep $INITIAL_WAIT

# Send command to wait for OMEMO initialization to complete
log "Client A: Ensuring OMEMO is fully initialized"
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" "Ctrl+O" # Assuming Ctrl+O is a key combo to trigger OMEMO status check
sleep $ACTION_DELAY

log "Client B: Ensuring OMEMO is fully initialized"
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "Ctrl+O" # Assuming Ctrl+O is a key combo to trigger OMEMO status check
sleep $ACTION_DELAY

log "Client A: Adding contact $CLIENT_B_JID"
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" C-a           # Ctrl+A to open Add Contact dialog
sleep $ACTION_DELAY
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" "$CLIENT_B_JID" # Send literal keys
sleep $KEY_DELAY
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" Enter
sleep $ACTION_DELAY

log "Client B: Adding contact $CLIENT_A_JID"
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" C-a           # Ctrl+A to open Add Contact dialog
sleep $ACTION_DELAY
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "$CLIENT_A_JID" # Send literal keys
sleep $KEY_DELAY
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" Enter
sleep $ACTION_DELAY

log "Waiting $OMEMO_WAIT seconds for OMEMO setup (device list exchange)..."
sleep $OMEMO_WAIT

# Add explicit checks for device list synchronization before proceeding with trust establishment
log "Ensuring device lists are synchronized..."
DEVICE_SYNC_WAIT=10 # Wait time for device list synchronization
MAX_SYNC_ATTEMPTS=5 # Maximum number of attempts to check synchronization
SYNC_ATTEMPT=0
SYNC_SUCCESS=false

while [ $SYNC_ATTEMPT -lt $MAX_SYNC_ATTEMPTS ]; do
    log "Checking device list synchronization (attempt $((SYNC_ATTEMPT + 1))/$MAX_SYNC_ATTEMPTS)..."
    CLIENT_A_DEVICES=$("$TMUX_CMD" capture-pane -p -t "$CLIENT_A_TARGET" | grep -c "Device list updated")
    CLIENT_B_DEVICES=$("$TMUX_CMD" capture-pane -p -t "$CLIENT_B_TARGET" | grep -c "Device list updated")

    if [ "$CLIENT_A_DEVICES" -gt 0 ] && [ "$CLIENT_B_DEVICES" -gt 0 ]; then
        log "Device lists synchronized successfully."
        SYNC_SUCCESS=true
        break
    fi

    log "Device lists not yet synchronized. Waiting $DEVICE_SYNC_WAIT seconds before retrying..."
    sleep $DEVICE_SYNC_WAIT
    SYNC_ATTEMPT=$((SYNC_ATTEMPT + 1))
done

if ! $SYNC_SUCCESS; then
    log "ERROR: Device lists failed to synchronize after $MAX_SYNC_ATTEMPTS attempts."
    exit 1
fi

# Proceed with trust establishment after synchronization
log "Proceeding with trust establishment..."

log "Client A: Pre-emptively trusting Client B's devices"
# Select Client B (should be the first/only one after adding)
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" Down # Navigate down if needed (adjust based on UI)
sleep $KEY_DELAY
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" C-t  # Ctrl+T to toggle trust
sleep $KEY_DELAY
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" Enter
sleep $ACTION_DELAY

log "Client B: Pre-emptively trusting Client A's devices"
# Select Client A (should be the first/only one after adding)
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" Down # Navigate down if needed (adjust based on UI)
sleep $KEY_DELAY
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" C-t  # Ctrl+T to toggle trust
sleep $KEY_DELAY
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" Enter
sleep $ACTION_DELAY

log "Pausing $TRUST_DELAY seconds after trust toggle..."
sleep $TRUST_DELAY

# --- Before sending messages, verify that OMEMO bundles are published and devices can communicate ---
log "Verifying OMEMO bundles are published and synchronized..."
BUNDLE_SYNC_WAIT=10
MAX_BUNDLE_ATTEMPTS=3
BUNDLE_ATTEMPT=0
BUNDLE_SUCCESS=false

while [ $BUNDLE_ATTEMPT -lt $MAX_BUNDLE_ATTEMPTS ]; do
    log "Checking OMEMO bundle synchronization (attempt $((BUNDLE_ATTEMPT + 1))/$MAX_BUNDLE_ATTEMPTS)..."
    
    # Check for OMEMO bundle publication indicators
    CLIENT_A_BUNDLE=$("$TMUX_CMD" capture-pane -p -t "$CLIENT_A_TARGET" | grep -c "Bundle publication complete")
    CLIENT_B_BUNDLE=$("$TMUX_CMD" capture-pane -p -t "$CLIENT_B_TARGET" | grep -c "Bundle publication complete")
    
    # Also check for any trust indicators
    CLIENT_A_TRUST=$("$TMUX_CMD" capture-pane -p -t "$CLIENT_A_TARGET" | grep -c "Device marked as trusted")
    CLIENT_B_TRUST=$("$TMUX_CMD" capture-pane -p -t "$CLIENT_B_TARGET" | grep -c "Device marked as trusted")

    if ([ "$CLIENT_A_BUNDLE" -gt 0 ] && [ "$CLIENT_B_BUNDLE" -gt 0 ]) || \
       ([ "$CLIENT_A_TRUST" -gt 0 ] && [ "$CLIENT_B_TRUST" -gt 0 ]); then
        log "OMEMO bundles published and devices prepared for encryption."
        BUNDLE_SUCCESS=true
        break
    fi

    log "OMEMO bundles not yet synchronized. Waiting $BUNDLE_SYNC_WAIT seconds before retrying..."
    sleep $BUNDLE_SYNC_WAIT
    BUNDLE_ATTEMPT=$((BUNDLE_ATTEMPT + 1))
done

if ! $BUNDLE_SUCCESS; then
    log "WARNING: OMEMO bundle verification couldn't confirm full synchronization. Proceeding anyway..."
fi

# Force selection of contacts in both clients to ensure proper targets for messages
log "Ensuring contacts are selected in both clients..."
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" C-r  # Ctrl+R to refresh roster/contacts
sleep $ACTION_DELAY
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" Down # Navigate to select the contact
sleep $KEY_DELAY
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" Enter # Select the contact
sleep $ACTION_DELAY

"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" C-r  # Ctrl+R to refresh roster/contacts
sleep $ACTION_DELAY
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" Down # Navigate to select the contact
sleep $KEY_DELAY
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" Enter # Select the contact
sleep $ACTION_DELAY

log "Client A: Sending message to Client B"
# Ensure Client B is still selected in Client A's roster
# No extra navigation needed if trust toggle kept selection
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" "Hello from Client A! OMEMO test."
sleep $KEY_DELAY
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" Enter
sleep $ACTION_DELAY

log "Client B: Sending message to Client A"
# Ensure Client A is still selected in Client B's roster
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" "Hello from Client B! OMEMO works."
sleep $KEY_DELAY
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" Enter
sleep $ACTION_DELAY

# --- Message Reception Verification ---
log "Waiting for message reception (10 seconds)..."
sleep 10 # Give some time for messages to be delivered

# Enhanced verification with detailed debug info
log "Performing enhanced message verification with debug information..."

# Collect detailed OMEMO status information from both clients
"$TMUX_CMD" send-keys -t "$CLIENT_A_TARGET" C-o  # Assuming Ctrl+O shows OMEMO status
sleep $ACTION_DELAY
"$TMUX_CMD" send-keys -t "$CLIENT_B_TARGET" C-o  # Same for client B
sleep $ACTION_DELAY

# Capture full screen output for both clients for more comprehensive debugging
CLIENT_A_OUTPUT=$("$TMUX_CMD" capture-pane -p -t "$CLIENT_A_TARGET")
CLIENT_B_OUTPUT=$("$TMUX_CMD" capture-pane -p -t "$CLIENT_B_TARGET")

# Save all debugging info, regardless of test result
echo "$CLIENT_A_OUTPUT" > "client_a_screen_debug.log"
echo "$CLIENT_B_OUTPUT" > "client_b_screen_debug.log"

# Look for message patterns in both directions
A_RECEIVED_FROM_B=$(echo "$CLIENT_A_OUTPUT" | grep -c "Hello from Client B! OMEMO works.")
B_RECEIVED_FROM_A=$(echo "$CLIENT_B_OUTPUT" | grep -c "Hello from Client A! OMEMO test.")

# Also check for any OMEMO encryption indicators and errors
OMEMO_ENCRYPTION_A=$(echo "$CLIENT_A_OUTPUT" | grep -c "OMEMO encryption enabled\|message encrypted")
OMEMO_ENCRYPTION_B=$(echo "$CLIENT_B_OUTPUT" | grep -c "OMEMO encryption enabled\|message encrypted")
ENCRYPTION_ERRORS=$(echo "$CLIENT_A_OUTPUT $CLIENT_B_OUTPUT" | grep -c "Failed to encrypt\|Encryption error\|Couldn't find keys")

log "Encryption indicators - Client A: $OMEMO_ENCRYPTION_A, Client B: $OMEMO_ENCRYPTION_B"
if [ "$ENCRYPTION_ERRORS" -gt 0 ]; then
    log "WARNING: Detected $ENCRYPTION_ERRORS potential encryption errors."
fi

TEST_SUCCESS=true

# Verify message reception from B to A (primary issue)
log "Verifying Client A received message from Client B..."
if [ "$A_RECEIVED_FROM_B" -gt 0 ]; then
    log "SUCCESS: Client A received the message from Client B!"
else
    log "ERROR: Client A did not receive the message from Client B."
    # Mark the test as failed
    TEST_SUCCESS=false
fi

# Verify message reception from A to B
log "Verifying Client B received message from Client A..."
if [ "$B_RECEIVED_FROM_A" -gt 0 ]; then
    log "SUCCESS: Client B received the message from Client A!"
else
    log "ERROR: Client B did not receive the message from Client A."
    # Mark the test as failed
    TEST_SUCCESS=false
fi

# Set default success state if not already set to false
TEST_SUCCESS=${TEST_SUCCESS:-true}

# --- Test Finished ---
log "Automated interactions and verification complete."
if $TEST_SUCCESS; then
    log "OVERALL TEST RESULT: PASSED ✅"
else
    log "OVERALL TEST RESULT: FAILED ❌"
    # If needed, set an exit code that will be read by the parent script
    # This won't execute immediately due to the trap, but will be the script's exit code
    exit 1
fi

# --- Test Finished ---
log "Automated interactions sent."
log "Script finished its tasks. Pausing for 10 seconds before cleanup..."
sleep 10
log "Pause finished. Cleanup trap will now run."

# No need to attach or exit explicitly here; the trap handles cleanup and exit.
# The script ending will trigger the EXIT trap.
