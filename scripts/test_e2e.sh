#!/bin/bash

# This script is a wrapper that sets up the tmux environment for the E2E test
# and launches the main test logic script (test_e2e_logic.sh) in the first pane.

set -e # Exit immediately if a command exits with a non-zero status.
set -u # Treat unset variables as an error when substituting.
# set -x # Print commands and their arguments as they are executed. Useful for debugging.

# --- Configuration ---
CREDENTIALS_FILE=".github/test_credentials.json"
TMUX_SESSION="sermo-e2e-test"
SCRIPT_PANE=0 # Pane where test_e2e_logic.sh runs
CLIENT_A_PANE=1 # Pane for Client A application
CLIENT_B_PANE=2 # Pane for Client B application
LOGIC_SCRIPT="./scripts/test_e2e_logic.sh"

# --- Helper Functions ---

log() {
    # Log messages from the wrapper script will appear in the terminal where it's invoked
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [Wrapper] $1"
}

# No cleanup function needed in the wrapper, logic script handles it via trap

# --- Main Script ---

log "Starting E2E test wrapper script..."

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
if [ ! -f "$LOGIC_SCRIPT" ]; then
    log "Error: Logic script not found at $LOGIC_SCRIPT"
    exit 1
fi
if [ ! -x "$LOGIC_SCRIPT" ]; then
    log "Error: Logic script $LOGIC_SCRIPT is not executable. Please run: chmod +x $LOGIC_SCRIPT"
    exit 1
fi
if [ ! -f "Cargo.toml" ]; then
    log "Error: Cargo.toml not found. Run this script from the project root."
    exit 1
fi
log "Prerequisites met."

# 2. Setup Tmux
log "Ensuring no previous session named '$TMUX_SESSION' exists..."
"$TMUX_CMD" kill-session -t "$TMUX_SESSION" 2>/dev/null || true # Kill existing session if it exists, ignore errors

log "Setting up detached tmux session '$TMUX_SESSION' with 3 panes..."
# Start session, Pane 0 gets a bash shell
"$TMUX_CMD" new-session -d -s "$TMUX_SESSION" -n "Sermo E2E" bash

# Split Pane 0 vertically (-v). The new pane (1) is created *above* Pane 0.
# Pane 0 will be our script/log pane at the bottom.
"$TMUX_CMD" split-window -v -t "$TMUX_SESSION:0.$SCRIPT_PANE"

# Split the new top pane (Pane 1) horizontally (-h).
# This creates Pane 2 to the right of Pane 1.
# Pane 1 (top-left) is for Client A.
# Pane 2 (top-right) is for Client B.
"$TMUX_CMD" split-window -h -t "$TMUX_SESSION:0.$CLIENT_A_PANE"

# Remove the automatic layout selection
# "$TMUX_CMD" select-layout -t "$TMUX_SESSION:0" tiled 

log "Tmux session created. Layout: [A|B] over [Logs]"

# 3. Launch Logic Script in Pane 0
log "Launching logic script '$LOGIC_SCRIPT' in Pane $SCRIPT_PANE (Bottom)..."

# Define the command to run in Pane 0. Export necessary variables.
# Ensure the logic script path is correct relative to the execution directory.
# Pass the found TMUX_CMD path to the logic script via environment variable
# Pipe the logic script's output (stdout & stderr) through tee to capture it to a file
SCRIPT_LOG_FILE="e2e_script_output.log"
log "Logic script output will be captured to: $SCRIPT_LOG_FILE"
CMD="export TMUX_SESSION='$TMUX_SESSION' CLIENT_A_PANE='$CLIENT_A_PANE' CLIENT_B_PANE='$CLIENT_B_PANE' TMUX_CMD='$TMUX_CMD'; $LOGIC_SCRIPT 2>&1 | tee '$SCRIPT_LOG_FILE'; echo '[INFO] Logic script finished. Cleanup trap should have executed. Pane will close on session end.'"

# Send the command to Pane 0
"$TMUX_CMD" send-keys -t "$TMUX_SESSION:0.$SCRIPT_PANE" "$CMD" Enter

log "Logic script launched."

# --- Automatically Attach to Session --- 
log "Attaching to tmux session '$TMUX_SESSION'..."
# The session will automatically end when the logic script finishes and runs its cleanup.
"$TMUX_CMD" attach-session -t "$TMUX_SESSION"

log "Detached from session (it likely finished). Wrapper script complete."
log "Please check client_a_chatterbox.log and client_b_chatterbox.log for detailed logs."
exit 0 