# Chatterbox

This is a secure terminal chat application
implementing XMPP and OMEMO. It is proudly made with Rust.

![chatterbox](.github/chatterbox.png)

## Project Stats

- Total lines of Rust code: 32994 lines
  - OMEMO implementation: 16071 lines
  - XMPP integration: 9788 lines
  - UI and app logic: 7135 lines
  - Unsafe Rust: 0 lines

## Implemented XEPs

This currently implements the following XMPP Extension Protocols:

- XEP-0030: Service Discovery (feature and identity discovery)
- XEP-0085: Chat State Notifications (typing indicators)
- XEP-0115: Entity Capabilities (compact feature advertisement)
- XEP-0184: Message Delivery Receipts (delivery status tracking)
- XEP-0198: Stream Management (resumable connections / reconnection)
- XEP-0280: Message Carbons (sync messages across devices)
- XEP-0313: Message Archive Management (message history)
- XEP-0319: Last User Interaction in Presence (idle timestamps)
- XEP-0334: Message Processing Hints (store / no-store hints)
- XEP-0359: Unique and Stable Stanza IDs (sender-authored origin-id)
- XEP-0380: Explicit Message Encryption (EME indicator on encrypted messages)
- XEP-0384: OMEMO Encryption (end-to-end encryption)

The implementation also relies on two standard building blocks: XEP-0202 (Delayed Delivery) and XEP-0297 (Message Forwarding, used by Message Carbons).


## Out of Scope

The following features are intentionally not implemented:

- XEP-0045 / XEP-0367: Multi-user chat (group chat) and OMEMO in MUC
- XEP-0363: HTTP File Upload (file/image transfer) — text messages only
- XEP-0077: In-band registration — an existing XMPP account is required


## Setup Instructions

Run the following command to build the project:

   ```bash
   cargo build && cargo run
   ```

## Architecture and Implementation

See DESIGN.md for the design.

## Contributing

Feel free to submit issues or pull requests if you have suggestions or improvements for the project.
