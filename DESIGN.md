# Sermo XMPP Chat Client - Design Overview

## 1. Introduction

Sermo is a terminal-based XMPP (Extensible Messaging and Presence Protocol) chat client written in Rust. It aims to provide essential chat functionalities, including messaging, contact management, presence, delivery receipts, and typing notifications, within a terminal user interface (TUI).

## 2. Architecture

The application follows a modular, asynchronous, and event-driven architecture:

*   **Asynchronous:** Built upon the `tokio` runtime, enabling non-blocking I/O for network operations (XMPP) and UI responsiveness.
*   **Modular:** Code is organized into distinct modules based on functionality (UI, XMPP communication, data models, utilities, credentials, encryption). The XMPP module itself is further subdivided based on specific XMPP Extension Protocols (XEPs).
*   **Event-Driven:** The main application loop reacts to events originating from user input (via `crossterm`), the XMPP client (incoming messages, presence changes, receipts), and internal timers (e.g., for typing status).
*   **Terminal UI (TUI):** Uses the `ratatui` library (and `crossterm` backend) to render the user interface directly in the terminal.
*   **Client-Server:** Interacts with a standard XMPP server for all communication.

## 3. Core Components

*   **`main.rs`:**
    *   The application entry point.
    *   Handles command-line arguments (implicitly via environment variables for credentials).
    *   Manages application startup and shutdown.
    *   Initializes logging, credential loading/prompting.
    *   Sets up the `XMPPClient` and the `ChatUI`.
    *   Runs the main event loop, orchestrating interactions between the UI and the XMPP client.
    *   Handles terminal setup and restoration.
*   **`lib.rs`:**
    *   Defines the library crate root.
    *   Re-exports core modules and types for external use (primarily testing in this case).
    *   Contains integration and unit tests for various components.
*   **`ui.rs`:**
    *   Manages the entire Terminal User Interface using `ratatui`.
    *   Defines the layout (Contacts pane, Chat pane, Input box).
    *   Handles user input events (keystrokes for typing, navigation, sending messages, switching focus).
    *   Renders messages, contact list, presence status, delivery status, and typing indicators.
    *   Manages UI state (active tab, selected contact, input buffer).
*   **`xmpp/` (Module Root: `xmpp/mod.rs`):**
    *   Encapsulates all XMPP communication logic using `tokio-xmpp` and `xmpp-parsers`.
    *   Manages the connection lifecycle (connect, disconnect, reconnect attempts).
    *   Handles the main XMPP event stream in an asynchronous task (`handle_incoming_messages`).
    *   Provides methods for core XMPP actions (sending messages, fetching roster, sending presence/chat states).
    *   Contains submodules for specific XEP implementations:
        *   `delivery_receipts.rs`: Implements XEP-0184 (Message Delivery Receipts). Handles sending receipt requests and processing incoming receipts.
        *   `chat_states.rs`: Implements XEP-0085 (Chat State Notifications). Handles sending and receiving typing indicators (composing, paused, active).
        *   `message_archive.rs`: Implements XEP-0313 (Message Archive Management - MAM). Handles querying the server for message history.
        *   `omemo_integration.rs`: Handles the integration of OMEMO encryption (XEP-0384) with the XMPP message flow. This includes processing OMEMO stanzas, interacting with the `OmemoManager` for encryption/decryption, and managing XMPP PubSub interactions for OMEMO bundle and device list publication/retrieval.
*   **`omemo/` (Module Root: `omemo/mod.rs`):**
    *   Contains the core logic for OMEMO end-to-end encryption. Key components include the `OmemoManager` (in `manager.rs`) which orchestrates cryptographic operations, session management, and interaction with the OMEMO store. It also includes modules for cryptographic primitives (`crypto.rs`), session state (`session.rs`), X3DH and Double Ratchet protocol logic (e.g. `x3dh.rs`, `double_ratchet.rs`), and key/identity storage (`store.rs`).
*   **`models.rs`:**
    *   Defines core data structures used throughout the application, such as `Message`, `DeliveryStatus`, `ContactStatus`, etc. Ensures consistent data representation.
*   **`credentials.rs`:**
    *   Handles the loading and saving of user credentials (server, username, password) securely, likely to a configuration file.
*   **`auth.rs`:**
    *   Appears related to authentication or credential management, potentially overlapping with `credentials.rs`. (Further investigation might clarify its specific role).
*   **`utils.rs`:**
    *   Contains miscellaneous utility functions, such as setting up logging (`log` crate) and reading lines from standard input.

## 4. Key Features & XEPs Implemented

*   **XMPP Connection & Authentication:** Basic connection and SASL authentication.
*   **Roster Management (jabber:iq:roster):** Fetching the user's contact list.
*   **Presence (RFC 6121):** Sending user presence and receiving contact presence updates (Online, Offline, Away).
*   **Basic Messaging (RFC 6121):** Sending and receiving one-to-one chat messages.
*   **Message Delivery Receipts (XEP-0184):** Tracking message status (Sent, Delivered).
*   **Chat State Notifications (XEP-0085):** Displaying typing indicators.
*   **Message Archive Management (XEP-0313):** Retrieving message history from the server.
*   **Message Carbons (XEP-0280):** Synchronizing messages sent/received by other clients for the same account.
*   **OMEMO Encryption (XEP-0384):** End-to-end encryption for messages (implementation details in `omemo/`).

## 5. Concurrency and State Management

*   **`tokio`:** Used for the asynchronous runtime, managing tasks for network I/O, UI events, and background processing (like history loading).
*   **`Arc<TokioMutex<T>>`:** Used to safely share mutable state (like the `XMPPAsyncClient` instance and the `pending_receipts` map) across different asynchronous tasks.
*   **`tokio::sync::mpsc` Channels:** Used for communication between asynchronous tasks. Examples:
    *   XMPP event handler sends received `Message` objects to the main loop/UI task.
    *   Main loop sends commands (like "send message") to the XMPP task (implicitly via client methods).
    *   Presence updates are broadcast to subscribers (the UI) via a shared channel.
    *   Typing notifications are sent from the XMPP handler to the UI via a channel.
    *   Background history loading task sends results back to the main message channel.

## 6. Key Dependencies

*   **`tokio`:** Asynchronous runtime.
*   **`ratatui`:** Terminal UI rendering.
*   **`crossterm`:** Terminal manipulation and event handling backend for `ratatui`.
*   **`tokio-xmpp`:** Core XMPP client library.
*   **`xmpp-parsers`:** Parsing XMPP XML stanzas.
*   **`log` / `env_logger`:** Logging framework.
*   **`anyhow`:** Error handling.
*   **`uuid`:** Generating unique IDs (e.g., for messages, stanza tracking).
*   **`serde`:** Serialization/Deserialization (likely for credentials).
*   **`lazy_static`:** For static variables with non-const initializers (e.g., shared channels).
*   **OMEMO Dependencies:** Likely includes cryptographic libraries (`curve25519-dalek`, `aes-gcm`, etc.) and potentially database libraries (`rusqlite`) for storage.

## 7. OMEMO Encryption Implementation

OMEMO (XEP-0384) is an end-to-end encryption protocol for XMPP based on the Signal Double Ratchet Algorithm. Here's how it's implemented in Sermo:

### 7.1 Core Principles

*   **Double Ratchet Algorithm:** Provides forward secrecy and break-in recovery properties.
*   **Key Management:** Each device generates identity keys and session keys.
*   **Device Registration:** Devices publish their identity keys and device information to the server.
*   **Session Establishment:** Sessions are established between devices by exchanging key bundles.
*   **Message Encryption:** Messages are encrypted with unique message keys derived from the Double Ratchet.

### 7.2 Implementation Details

*   **Device Identity:**
    *   Each client instance generates an identity key pair (Curve25519).
    *   This identity remains consistent across restarts for the same device.
    *   Stored securely in the local device storage.

*   **Key Bundles:**
    *   Contains identity key, signed pre-keys, and a set of one-time pre-keys.
    *   Published to the server using PEP (Personal Eventing Protocol).
    *   Other devices fetch these bundles to establish sessions.

*   **Session Management:**
    *   Sessions are established between each pair of devices.
    *   The Double Ratchet state is maintained for each active session.
    *   Sessions persist across application restarts.

*   **Message Encryption Process:**
    1. The `OmemoManager` encrypts the plaintext message content with a new, unique message key.
    2. For each intended recipient device (including the sender's own other devices, if applicable):
        a. The `OmemoManager` retrieves or establishes a secure OMEMO session (Double Ratchet) with that device. This may involve fetching the device's bundle from the PubSub service if a session doesn't already exist.
        b. The unique message key is then encrypted using this established OMEMO session.
    3. The encrypted message payload and the collection of encrypted message keys (one per recipient device) are packaged into an XMPP `<message>` stanza with an `<encrypted>` OMEMO element.
    4. The `XMPPClient` sends this stanza.

*   **Message Decryption Process:**
    1. Upon receiving an XMPP message containing an OMEMO `<encrypted>` element, the `XMPPClient` passes it to the `xmpp/omemo_integration.rs` handler.
    2. This handler, in turn, invokes the `OmemoManager`.
    3. The `OmemoManager` inspects the OMEMO headers to find the encrypted message key intended for the current device.
    4. It uses the pre-established OMEMO session (Double Ratchet) with the sender's device to decrypt this message key.
    5. Once the unique message key is decrypted, the `OmemoManager` uses it to decrypt the actual message payload.
    6. The decrypted plaintext is then made available to the application (e.g., for display in the UI).

### 7.3 Technical Components

*   **Key Storage (`omemo/storage.rs`):**
    *   Securely stores identity keys, session states, and pre-keys.
    *   Uses file-based or database storage with appropriate encryption.

*   **Cryptographic Operations (`omemo/crypto.rs`):**
    *   Handles all cryptographic primitives (Curve25519, AES-GCM, etc.).
    *   Provides key generation, signing, and verification.
    *   Implements the Double Ratchet Algorithm for message key derivation.

*   **Protocol Implementation (`omemo/protocol.rs`):**
    *   Implements the OMEMO protocol details.
    *   Handles XML stanza structure for OMEMO elements.
    *   Manages device list publication and updates.

*   **Session Management (`omemo/session.rs`):**
    *   Manages the lifecycle of encryption sessions.
    *   Handles session establishment, updates, and termination.
    *   Implements the Double Ratchet state machine.

*   **XMPP Integration (`xmpp/omemo_integration.rs`):**
    *   Connects OMEMO functionality with the XMPP client. Intercepts outgoing messages for encryption and processes incoming encrypted messages for decryption. Crucially, it also handles the XMPP PubSub (PEP) interactions required by OMEMO, such as publishing the local device's bundle and fetching bundles and device lists for contacts.

### 7.4 Security Considerations

*   **Trust Verification:**
    *   Users can verify the fingerprints of their contacts' devices.
    *   Manual verification is recommended for sensitive communications.

*   **Multiple Device Support:**
    *   Messages are encrypted separately for each of a user's devices.
    *   Device list synchronization ensures all active devices receive messages.

*   **Forward Secrecy:**
    *   Even if keys are compromised, past messages cannot be decrypted.
    *   Regular key rotation enhances security.

*   **Metadata Protection:**
    *   While message content is encrypted, metadata (sender, recipient, timestamp) remains visible to the server.
    *   Users should be aware of these limitations.

The OMEMO implementation in Sermo prioritizes security while maintaining usability. It achieves this by handling the complex cryptographic operations transparently, allowing users to communicate securely without needing to understand the underlying encryption details.
