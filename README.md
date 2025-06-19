# CLI Chat Application

This is a command-line interface (CLI) chat application
using XMPP and OMEMO. It is proudly made with Rust.

## Project Stats

- Total lines of Rust code: 18282 lines
- Fully implemented OMEMO encryption (XEP-0384)
- Core modules:
- OMEMO implementation: 5934 lines
- XMPP integration: 9030 lines
- UI and app logic: 3318 lines

## Features

- Real-time chat functionality using XMPP protocol.
- User-friendly command-line interface.
- Support for sending and receiving messages.
- Display of chat history and incoming messages.

## Implemented XEPs

The application currently implements the following XMPP Extension Protocols:

- XEP-0184: Message Delivery Receipts (delivery status tracking)
- XEP-0313: Message Archive Management (message history)
- XEP-0085: Chat State Notifications (typing indicators)
- XEP-0280: Message Carbons (sync messages across devices)
- XEP-0384: OMEMO Encryption

## Setup Instructions

Run the following command to build the project:

   ```bash
   cargo build && cargo run
   ```


## Architecture and Implementation

The CLI Chat Application uses multiple threads:

1. **Main UI Thread**
   - Renders the terminal UI and handles user input
   - Processes outgoing message requests
   - Updates the UI with incoming messages and status updates
   - Never blocks on network operations to maintain UI responsiveness

2. **Background Worker Threads**
   - **XMPP Event Handler Thread**: Continuously listens for incoming XMPP events (messages, presence updates)

3. **Message History Thread**: Asynchronously loads message history without blocking the UI

4. **Typing Notification Thread**: Sends chat state notifications in the background


The application employs several key locking strategies:

1. **Short-lived, Scoped Locks**
   - Operations that need access to the XMPP client use brief, scoped locks
   - Locks are held only for the minimal duration needed for critical operations
   - Example: When fetching message history, locks are briefly acquired to send the query and check for responses, then released between operations

2. **Tokio Mutex (`TokioMutex`)**
   - Used for protecting shared resources in asynchronous context
   - Core XMPP client connection is protected by a `TokioMutex` that ensures only one operation can access it at a time
   - All locks use timeouts to prevent deadlocks

3. **Message Passing**
   - Inter-thread communication primarily uses Tokio channels instead of shared state
   - UI updates are sent through channels from background threads to the main UI thread
   - Typing indicators, presence updates, and messages all flow through dedicated channels

#### Deadlock Prevention

1. **Lock Timeouts**
   - All lock acquisition attempts have timeouts to prevent indefinite blocking
   - Example: Message history retrieval will timeout after 5 seconds if it cannot acquire a lock

2. **Fire-and-Forget Operations**
   - Non-critical operations like typing indicators use a "fire-and-forget" approach
   - They attempt to acquire locks with `try_lock()` and gracefully skip the operation if the lock is busy

3. **Background Task Isolation**
   - Long-running operations are isolated in separate tasks with their own client clones
   - These tasks handle their own error cases and only communicate results back through channels

This architecture ensures that the UI remains responsive even when network operations are slow or blocked, and it allows multiple operations (message sending, history retrieval, typing notifications) to proceed concurrently without interfering with each other.

## Dependencies

- `ratatui`: For rendering the user interface.
- `xmpp`: For handling XMPP communication.

## Contributing

Feel free to submit issues or pull requests if you have suggestions or improvements for the project.
