# Chatterbox XMPP Chat Client - Design Overview

## 1. Introduction

Chatterbox is a terminal-based XMPP (Extensible Messaging and Presence Protocol) chat client written in Rust. It provides messaging, contact management, presence, delivery receipts, typing notifications, local message persistence, and OMEMO end-to-end encryption within a terminal user interface (TUI).

## 2. Architecture

The application follows a modular, asynchronous, and event-driven architecture:

*   **Asynchronous:** Built upon the `tokio` runtime, enabling non-blocking I/O for network operations (XMPP) and UI responsiveness.
*   **Modular:** Code is organized into distinct modules based on functionality (UI, XMPP communication, data models, utilities, credentials, encryption). The XMPP module itself is further subdivided based on specific XMPP Extension Protocols (XEPs).
*   **Event-Driven:** The main application loop reacts to events originating from user input (via `crossterm`), the XMPP client (incoming messages, presence changes, receipts), and internal timers (e.g., for typing status).
    The TUI loop blocks on `tokio::select!` instead of continuously polling and redrawing.
*   **Terminal UI (TUI):** Uses the `ratatui` library (and `crossterm` backend) to render the user interface directly in the terminal.
*   **Client-Server:** Interacts with a standard XMPP server for all communication.

## 3. Core Components

*   **`main.rs`:**
    *   Entry point (~280 lines).
    *   Handles command-line argument parsing and logging setup.
    *   Loads credentials and establishes the XMPP connection.
    *   Delegates to `app::run_app()` after successful connection.
*   **`app.rs`:**
    *   Application lifecycle: TUI setup, event loop, and command dispatch.
    *   Opens the local `MessageStore` on startup.
    *   Runs the main event loop with `tokio::select!`, orchestrating terminal events, XMPP events, timers, and the local store.
    *   Handles contact switching (loads local history instantly, then MAM catch-up).
    *   Persists all sent and received messages to the local store.
    *   Sends optional OS notifications for incoming messages using `notify-rust`, suppressing them while the terminal reports focus.
*   **`lib.rs`:**
    *   Defines the library crate root.
    *   Re-exports core modules and types for external use (primarily testing in this case).
    *   Contains integration and unit tests for various components.
*   **`ui.rs`:**
    *   Manages the entire Terminal User Interface using `ratatui`.
    *   Defines the layout (Contacts pane, Chat pane, Input box).
    *   Spawns `TerminalEventReader`, a small blocking crossterm reader thread that forwards terminal events into the async app loop.
    *   Handles user input events supplied by the app loop (keystrokes, terminal focus changes, typing, navigation, sending messages, switching panes).
    *   Renders messages, contact list, presence status, delivery status, and typing indicators.
    *   Manages UI state (active tab, selected contact, input buffer, dialogs, notification toggle, terminal focus).
*   **`xmpp/` (Module Root: `xmpp/mod.rs`):**
    *   Encapsulates all XMPP communication logic using `tokio-xmpp` and `xmpp-parsers`.
    *   Manages the connection lifecycle (connect, disconnect, reconnect attempts).
    *   Spawns `transport.rs`, a transport actor that owns `tokio_xmpp::AsyncClient` exclusively and multiplexes inbound XMPP events with outbound stanza sends through channels.
    *   Handles the XMPP event stream in `event_loop.rs` via `XMPPClient::handle_incoming_messages`.
    *   Provides methods for core XMPP actions (sending messages, fetching roster, sending presence/chat states) by sending stanzas through `transport::StanzaTx`.
    *   Contains submodules for specific XEP implementations:
        *   `delivery_receipts.rs`: Implements XEP-0184 (Message Delivery Receipts). Handles sending receipt requests and processing incoming receipts.
        *   `chat_states.rs`: Implements XEP-0085 (Chat State Notifications). Handles sending and receiving typing indicators (composing, paused, active).
        *   `message_archive.rs`: Implements XEP-0313 (Message Archive Management - MAM). Handles querying the server for message history.
        *   `message_carbons.rs`: Implements XEP-0280 (Message Carbons).
        *   `omemo_handler.rs` and `omemo_integration/`: Handle OMEMO stanza processing, encryption/decryption integration, and PubSub operations for bundle and device list publication/retrieval.
*   **`omemo/` (Module Root: `omemo/mod.rs`):**
    *   Contains the core logic for OMEMO end-to-end encryption. `OmemoManager` is defined in `omemo/mod.rs` and orchestrates cryptographic operations, session management, PubSub access, and interaction with `OmemoStorage`.
    *   Current modules include `bundle.rs`, `crypto.rs`, `decrypt.rs`, `device_discovery.rs`, `device_id.rs`, `encrypt.rs`, `lifecycle.rs`, `protocol.rs`, `session.rs`, `storage.rs`, and `wire.rs`.
*   **`models.rs`:**
    *   Defines core data structures used throughout the application, such as `Message`, `DeliveryStatus`, `ContactStatus`, etc. Ensures consistent data representation.
*   **`storage.rs`:**
    *   SQLite-backed local message persistence (`rusqlite` with bundled SQLite).
    *   Database per account at `~/.local/share/chatterbox/<jid>/messages.db`.
    *   Provides `MessageStore` with methods: `store_message`, `load_messages`, `newest_timestamp`, `update_delivery_status`.
    *   Idempotent inserts (`INSERT OR IGNORE`) allow safe replay of MAM results.
    *   Used as the primary source of history on contact switch; MAM becomes catch-up only.
*   **`credentials.rs`:**
    *   Handles loading and saving credentials and app settings.
    *   Credentials are stored in `credentials.json`; saved passwords are base64-encoded for storage, not encrypted.
    *   App settings such as the OS notification toggle are stored in `settings.json`.
*   **`utils.rs`:**
    *   Contains miscellaneous utility functions, such as setting up logging (`log` crate) and reading lines from standard input.

## 4. Key Features & XEPs Implemented

*   **XMPP Connection & Authentication:** Basic connection and SASL authentication.
*   **Roster Management (jabber:iq:roster):** Fetching the user's contact list.
*   **Presence (RFC 6121):** Sending user presence and receiving contact presence updates (Online, Offline, Away).
*   **Basic Messaging (RFC 6121):** Sending and receiving one-to-one chat messages.
*   **Message Delivery Receipts (XEP-0184):** Tracking message status (Sent, Delivered).
*   **Chat State Notifications (XEP-0085):** Displaying typing indicators.
*   **Message Archive Management (XEP-0313):** Retrieving message history from the server (used for catch-up only; local store is primary).
*   **Message Carbons (XEP-0280):** Synchronizing messages sent/received by other clients for the same account.
*   **OMEMO Encryption (XEP-0384):** End-to-end encryption for messages (implementation details in `omemo/`).
*   **Local Message Persistence:** SQLite-backed per-account message storage for instant history access offline.
*   **Optional OS Notifications:** Desktop notifications for incoming messages using `notify-rust`, disabled by default, persisted in app settings, and suppressed while the terminal is focused.

## 5. Concurrency and State Management

*   **`tokio`:** Used for the asynchronous runtime, managing tasks for network I/O, UI events, and background processing (like history loading).
*   **Transport actor:** `xmpp/transport.rs` owns `XMPPAsyncClient` exclusively. Outbound stanzas are sent to it through `StanzaTx`; inbound XMPP events are sent back over an event channel. The raw XMPP client is not shared behind a mutex.
*   **Event-driven UI loop:** `app.rs` waits on terminal events, incoming messages, presence updates, friend requests, typing notifications, and periodic timers with `tokio::select!`. The UI redraws only when state changes.
*   **Terminal event reader:** `ui.rs` uses a small blocking reader thread for `crossterm` events and forwards them to the async loop over a Tokio channel.
*   **Shared state:** `Arc<TokioMutex<T>>` is still used for scoped mutable state such as pending delivery receipts, IQ response routing, and the OMEMO manager, but not for the XMPP transport itself.
*   **`tokio::sync::mpsc` Channels:** Used for communication between asynchronous tasks. Examples:
    *   XMPP event handling sends received `Message` objects to the main loop/UI task.
    *   The app sends outbound stanzas through the transport channel via `XMPPClient` methods.
    *   Typing notifications are sent from the XMPP handler to the UI via a channel.
    *   Background history loading tasks send results back to the main message channel.
*   **`tokio::sync::broadcast` Channels:** Used for presence updates and auto-accepted friend request notifications.
*   **`tokio::sync::watch` Channel:** Publishes late-bound state such as the OMEMO manager, PubSub response map, local JID, and typing sender to the XMPP event loop after initialization.

## 6. Key Dependencies

*   **`tokio`:** Asynchronous runtime.
*   **`ratatui`:** Terminal UI rendering.
*   **`crossterm`:** Terminal manipulation and event handling backend for `ratatui`.
*   **`tokio-xmpp`:** Core XMPP client library.
*   **`xmpp-parsers`:** Parsing XMPP XML stanzas.
*   **`log`:** Logging facade, backed by the custom logger in `utils.rs`.
*   **`clap`:** Command-line argument parsing.
*   **`anyhow`:** Error handling.
*   **`uuid`:** Generating unique IDs (e.g., for messages, stanza tracking).
*   **`serde`:** Serialization/Deserialization (for credentials).
*   **`rusqlite`:** SQLite database access (bundled) for local message persistence.
*   **`notify-rust`:** Cross-platform OS desktop notifications.
*   **`chrono`:** Timestamp handling for MAM queries and message ordering.
*   **OMEMO Dependencies:** Cryptographic libraries (`curve25519-dalek`, `aes-gcm`, etc.) for end-to-end encryption.

## 7. OMEMO Encryption Implementation

OMEMO (XEP-0384) is an end-to-end encryption protocol for XMPP based on the Signal Double Ratchet Algorithm. Here's how it's implemented in Chatterbox:

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
    *   Stored in local OMEMO storage.

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
    1. Upon receiving an XMPP message containing an OMEMO `<encrypted>` element, the `XMPPClient` passes it through `xmpp/omemo_handler.rs` and the `xmpp/omemo_integration/` helpers.
    2. This handler, in turn, invokes the `OmemoManager`.
    3. The `OmemoManager` inspects the OMEMO headers to find the encrypted message key intended for the current device.
    4. It uses the pre-established OMEMO session (Double Ratchet) with the sender's device to decrypt this message key.
    5. Once the unique message key is decrypted, the `OmemoManager` uses it to decrypt the actual message payload.
    6. The decrypted plaintext is then made available to the application (e.g., for display in the UI).

### 7.3 Technical Components

*   **Key Storage (`omemo/storage.rs`):**
    *   Stores identity keys, session states, device IDs, trust state, and pre-key metadata.
    *   Uses local storage paths derived from the account or OMEMO directory override.

*   **Cryptographic Operations (`omemo/crypto.rs`):**
    *   Handles all cryptographic primitives (Curve25519, AES-GCM, etc.).
    *   Provides key generation, signing, and verification.
    *   Provides interop helpers such as XEdDSA verification and prefixed X25519 public key encoding.

*   **Protocol Implementation (`omemo/protocol.rs`):**
    *   Implements X3DH and Double Ratchet protocol details.
    *   Handles XML stanza structure for OMEMO elements.
    *   Manages device list publication and updates.

*   **Session Management (`omemo/session.rs`):**
    *   Manages the lifecycle of encryption sessions.
    *   Handles session establishment, updates, and termination.
    *   Implements the Double Ratchet state machine.

*   **XMPP Integration (`xmpp/omemo_handler.rs`, `xmpp/omemo_integration/`):**
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

The OMEMO implementation in Chatterbox prioritizes security while maintaining usability. It achieves this by handling the complex cryptographic operations transparently, allowing users to communicate securely without needing to understand the underlying encryption details.

## 8. Local Message Persistence

Chatterbox uses SQLite (via `rusqlite` with the `bundled` feature) to persist messages locally, making history available instantly without waiting for server round-trips.

### 8.1 Storage Layout

*   One database per account: `~/.local/share/chatterbox/<bare_jid>/messages.db`
*   Falls back to the OMEMO directory override if set (useful for tests and custom deployments).

### 8.2 Schema

```sql
CREATE TABLE messages (
    id              TEXT PRIMARY KEY,
    contact_jid     TEXT NOT NULL,
    sender_id       TEXT NOT NULL,
    recipient_id    TEXT NOT NULL,
    content         TEXT NOT NULL,
    timestamp       INTEGER NOT NULL,
    delivery_status INTEGER NOT NULL DEFAULT 0,
    encrypted       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_messages_contact_ts ON messages (contact_jid, timestamp);
```

### 8.3 Integration with MAM

1. On contact switch, the last 100 messages are loaded instantly from SQLite.
2. A background MAM catch-up query is issued with `start` set to `newest_local_timestamp + 1`.
3. Messages arriving from MAM are persisted via `INSERT OR IGNORE`, so duplicates are harmless.
4. If no local history exists, a full MAM fetch is performed (same as before).

### 8.4 Design Decisions

*   **Relational (SQLite):** Chosen for indexed range queries on `(contact_jid, timestamp)`, atomic upserts, and zero-config deployment (bundled).
*   **Idempotent writes:** `INSERT OR IGNORE` keyed on message ID ensures safe replay and deduplication.
*   **Synchronous access:** All store operations are fast local I/O and run on the main event loop — no need for async wrapping or cross-thread sharing.
*   **Graceful degradation:** If the store fails to open, the app continues without local persistence (MAM-only mode).

## 9. Message Construction Safety

The `Message` struct uses **factory functions** to prevent a class of bugs where fields like `encrypted` are set incorrectly at construction sites scattered across the codebase.

### 9.1 The Problem

With ~35 `Message` construction sites across 10+ files, manual struct literal construction led to bugs where:
*   OMEMO-encrypted messages were created with `encrypted: false` (causing incorrect UI indicators).
*   The `encrypted` field wasn't persisted to SQLite at all (schema omission).
*   Carbon copy echoes and own-device reflections had inconsistent field values.

### 9.2 Factory Functions

`Message` provides six factory constructors in `models.rs` that enforce correct field invariants by construction:

| Factory | `sender_id` | `encrypted` | `delivery_status` | Use case |
|---------|-------------|-------------|-------------------|----------|
| `outgoing_encrypted()` | `"me"` | `true` | `Sent` | Sending an OMEMO message |
| `outgoing_plaintext()` | `"me"` | `false` | `Sent` | Sending a plaintext message |
| `incoming_encrypted()` | sender JID | `true` | `Delivered` | Receiving an OMEMO message |
| `incoming_plaintext()` | sender JID | `false` | `Delivered` | Receiving a plaintext message |
| `system()` | `"system"` | `false` | `Delivered` | Notifications, key verification prompts |
| `delivery_update()` | `"me"` | caller-specified | caller-specified | Status updates (Sending→Delivered) |

### 9.3 Design Rules

*   **Production code** must use factory functions for all `Message` creation.
*   **Test code** may use struct literals to test specific field combinations.
*   **`delivery_status` overrides** are allowed via mutation after construction (e.g., carbon echoes set `Delivered` instead of the factory's default `Sent`).
*   Fields remain `pub` — the factories are a convention enforced by code review, not the type system. A future improvement could make fields private and add accessor methods.

### 9.4 Coverage

All ~35 production construction sites across `send.rs`, `omemo_handler.rs`, `message_carbons.rs`, `coordinator.rs`, `event_loop.rs`, `delivery_receipts.rs`, `ui.rs`, `app.rs`, and `omemo_integration/xmpp_client_impl.rs` use factory functions.

## 10. Transport and Coordinator Architecture

`xmpp/transport.rs` is part of the current runtime path. When `XMPPClient::connect()` succeeds, it spawns a transport actor that owns `tokio_xmpp::AsyncClient` and exposes channel handles for the rest of the XMPP layer:

*   **`StanzaTx`:** Cloneable sender for outbound XML stanzas.
*   **Transport event receiver:** Delivers `tokio_xmpp::Event` values (`Online`, `Stanza`, `Disconnected`) to `event_loop.rs`.
*   **No shared raw client mutex:** Senders never lock `XMPPAsyncClient`; they enqueue stanzas to the transport actor.
*   **Optional reconnect variants:** `spawn_transport_with_reconnect()` and bounded-channel variants exist for coordinator-style use.

`xmpp/coordinator.rs` remains an additional single-threaded coordinator pattern and testbed for a more command-oriented XMPP architecture. It provides:

*   **`CoordinatorState`:** All mutable state in one struct (no `Arc<Mutex<>>` needed).
*   **`send_to_ui()` helper:** Non-blocking `try_send()` to prevent channel backpressure from deadlocking the event loop.
*   **`TransportHandle`:** Bounded channels for stanza send/receive with automatic reconnection and exponential backoff.
*   **Command dispatch:** `CoordinatorCommand` enum for type-safe app→XMPP communication.

The current `main.rs` path still uses `XMPPClient`, `transport.rs`, and `event_loop.rs`; the coordinator is exported and heavily tested but is not the app entry point.
