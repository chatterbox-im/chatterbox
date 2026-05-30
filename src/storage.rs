// src/storage.rs
//! Local message persistence backed by SQLite.
//!
//! Messages are stored per-account in `~/.local/share/chatterbox/<jid>/messages.db`.
//! The store is designed to be the primary source of message history, with MAM
//! used only for initial sync and catch-up.

use anyhow::{anyhow, Result};
use log::info;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::PathBuf;

use crate::models::{DeliveryStatus, Message};

/// SQLite-backed local message store.
pub struct MessageStore {
    conn: Connection,
}

impl MessageStore {
    /// Open (or create) the message database for the given bare JID.
    /// The DB is placed alongside the OMEMO data in the user's data directory.
    pub fn open(jid: &str) -> Result<Self> {
        let db_path = Self::db_path(jid)?;

        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&db_path)?;
        let store = Self { conn };
        store.migrate()?;
        info!("Message store opened at {}", db_path.display());
        Ok(store)
    }

    /// Open an in-memory database (for testing).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Resolve the database file path for a given JID.
    fn db_path(jid: &str) -> Result<PathBuf> {
        // Respect the OMEMO dir override if set (for tests and custom deployments)
        if let Some(dir) = crate::omemo::device_id::get_omemo_dir_override() {
            return Ok(dir.join("messages.db"));
        }

        let mut path = dirs::data_dir()
            .ok_or_else(|| anyhow!("Could not determine data directory"))?;
        path.push("chatterbox");
        path.push(jid);
        path.push("messages.db");
        Ok(path)
    }

    /// Run schema migrations.
    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS messages (
                id          TEXT PRIMARY KEY,
                contact_jid TEXT NOT NULL,
                sender_id   TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                content     TEXT NOT NULL,
                timestamp   INTEGER NOT NULL,
                delivery_status INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_messages_contact_ts
                ON messages (contact_jid, timestamp);
            ",
        )?;
        Ok(())
    }

    /// Persist a message. Duplicate IDs are silently ignored (idempotent).
    pub fn store_message(&self, msg: &Message) -> Result<()> {
        let contact_jid = Self::contact_jid_for(msg);
        let status = msg.delivery_status as i32;

        self.conn.execute(
            "INSERT OR IGNORE INTO messages (id, contact_jid, sender_id, recipient_id, content, timestamp, delivery_status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                msg.id,
                contact_jid,
                msg.sender_id,
                msg.recipient_id,
                msg.content,
                msg.timestamp as i64,
                status,
            ],
        )?;
        Ok(())
    }

    /// Load the most recent `limit` messages for a contact, ordered oldest-first.
    pub fn load_messages(&self, contact_jid: &str, limit: usize) -> Result<Vec<Message>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sender_id, recipient_id, content, timestamp, delivery_status
             FROM messages
             WHERE contact_jid = ?1
             ORDER BY timestamp DESC
             LIMIT ?2",
        )?;

        let rows = stmt.query_map(params![contact_jid, limit as i64], |row| {
            Ok(Message {
                id: row.get(0)?,
                sender_id: row.get(1)?,
                recipient_id: row.get(2)?,
                content: row.get(3)?,
                timestamp: row.get::<_, i64>(4)? as u64,
                delivery_status: Self::status_from_i32(row.get(5)?),
            })
        })?;

        let mut messages: Vec<Message> = rows.filter_map(|r| r.ok()).collect();
        messages.reverse(); // oldest first
        Ok(messages)
    }

    /// Get the timestamp of the newest stored message for a contact.
    /// Used to determine where to start a MAM catch-up query.
    pub fn newest_timestamp(&self, contact_jid: &str) -> Result<Option<u64>> {
        let ts: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(timestamp) FROM messages WHERE contact_jid = ?1",
                params![contact_jid],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        Ok(ts.map(|t| t as u64))
    }

    /// Update the delivery status of a message by ID.
    pub fn update_delivery_status(&self, msg_id: &str, status: DeliveryStatus) -> Result<()> {
        self.conn.execute(
            "UPDATE messages SET delivery_status = ?1 WHERE id = ?2",
            params![status as i32, msg_id],
        )?;
        Ok(())
    }

    /// Determine which JID a message belongs to in the conversation index.
    /// For outgoing messages (sender = "me"/"You"), the contact is the recipient.
    /// For incoming messages, the contact is the sender (bare JID).
    fn contact_jid_for(msg: &Message) -> String {
        if msg.sender_id == "me" || msg.sender_id == "You" || msg.sender_id == "system" {
            msg.recipient_id.split('/').next().unwrap_or(&msg.recipient_id).to_string()
        } else {
            msg.sender_id.split('/').next().unwrap_or(&msg.sender_id).to_string()
        }
    }

    fn status_from_i32(val: i32) -> DeliveryStatus {
        match val {
            1 => DeliveryStatus::Sending,
            2 => DeliveryStatus::Sent,
            3 => DeliveryStatus::Stored,
            4 => DeliveryStatus::Delivered,
            5 => DeliveryStatus::Read,
            6 => DeliveryStatus::Failed,
            _ => DeliveryStatus::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_msg(id: &str, sender: &str, recipient: &str, content: &str, ts: u64) -> Message {
        Message {
            id: id.to_string(),
            sender_id: sender.to_string(),
            recipient_id: recipient.to_string(),
            content: content.to_string(),
            timestamp: ts,
            delivery_status: DeliveryStatus::Delivered,
        }
    }

    #[test]
    fn test_store_and_load() {
        let store = MessageStore::open_in_memory().unwrap();

        let m1 = make_msg("1", "alice@example.com", "me@example.com", "Hello", 1000);
        let m2 = make_msg("2", "me", "alice@example.com", "Hi back", 1001);
        let m3 = make_msg("3", "alice@example.com", "me@example.com", "How are you?", 1002);

        store.store_message(&m1).unwrap();
        store.store_message(&m2).unwrap();
        store.store_message(&m3).unwrap();

        let loaded = store.load_messages("alice@example.com", 50).unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].content, "Hello");
        assert_eq!(loaded[2].content, "How are you?");
    }

    #[test]
    fn test_newest_timestamp() {
        let store = MessageStore::open_in_memory().unwrap();

        let m1 = make_msg("1", "bob@example.com", "me@example.com", "Hey", 5000);
        let m2 = make_msg("2", "bob@example.com", "me@example.com", "Yo", 6000);
        store.store_message(&m1).unwrap();
        store.store_message(&m2).unwrap();

        let ts = store.newest_timestamp("bob@example.com").unwrap();
        assert_eq!(ts, Some(6000));

        let ts_none = store.newest_timestamp("unknown@example.com").unwrap();
        assert_eq!(ts_none, None);
    }

    #[test]
    fn test_idempotent_insert() {
        let store = MessageStore::open_in_memory().unwrap();

        let m1 = make_msg("dup", "alice@example.com", "me@example.com", "Hello", 1000);
        store.store_message(&m1).unwrap();
        store.store_message(&m1).unwrap(); // should not fail or duplicate

        let loaded = store.load_messages("alice@example.com", 50).unwrap();
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn test_update_delivery_status() {
        let store = MessageStore::open_in_memory().unwrap();

        let m1 = make_msg("msg1", "me", "alice@example.com", "Hello", 1000);
        store.store_message(&m1).unwrap();

        store.update_delivery_status("msg1", DeliveryStatus::Delivered).unwrap();

        let loaded = store.load_messages("alice@example.com", 50).unwrap();
        assert_eq!(loaded[0].delivery_status, DeliveryStatus::Delivered);
    }

    #[test]
    fn test_limit() {
        let store = MessageStore::open_in_memory().unwrap();

        for i in 0..100 {
            let m = make_msg(
                &format!("msg{}", i),
                "alice@example.com",
                "me@example.com",
                &format!("Message {}", i),
                1000 + i,
            );
            store.store_message(&m).unwrap();
        }

        let loaded = store.load_messages("alice@example.com", 20).unwrap();
        assert_eq!(loaded.len(), 20);
        // Should be the 20 most recent, oldest first
        assert_eq!(loaded[0].content, "Message 80");
        assert_eq!(loaded[19].content, "Message 99");
    }
}
