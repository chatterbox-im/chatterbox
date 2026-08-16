# Chatterbox

This is a secure terminal chat application
implementing XMPP and OMEMO. It is proudly made with Rust.

![chatterbox](.github/chatterbox.png)

## Project Stats

- Total lines of Rust code: 31634 lines
  - OMEMO implementation: 15589 lines
  - XMPP integration: 9773 lines
  - UI and app logic: 6272 lines
  - Unsafe Rust: 0 lines

## Implemented XEPs

This currently implements the following XMPP Extension Protocols:

- XEP-0184: Message Delivery Receipts (delivery status tracking)
- XEP-0313: Message Archive Management (message history)
- XEP-0085: Chat State Notifications (typing indicators)
- XEP-0280: Message Carbons (sync messages across devices)
- OMEMO Encryption 0.3


## Setup Instructions

Run the following command to build the project:

   ```bash
   cargo build && cargo run
   ```

## Architecture and Implementation

See DESIGN.md for the design.

## Contributing

Feel free to submit issues or pull requests if you have suggestions or improvements for the project.
