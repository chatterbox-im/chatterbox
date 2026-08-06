// src/omemo/store_sqlite.rs
//! SQLite-backed persistence for OMEMO state.
//!
//! This replaces the previous hand-rolled tree of directories, bincode blobs
//! and stringly-typed marker files (`rebuild_needed`, `prekey_pending_since`,
//! `failure_count`, …).  Three defects motivated the move, all of which this
//! module retires structurally rather than case-by-case:
//!
//! 1. **No format versioning.**  Sessions were persisted with bare `bincode`,
//!    which is not self-describing, so `#[serde(default)]` could not make a
//!    newly-added field backward compatible — an older `state.bin` simply
//!    failed with `io error: unexpected end of file`.  Every blob written here
//!    carries an explicit magic + version header (see [`encode_blob`]), so a
//!    future field addition is a decode branch rather than a data-loss event.
//!
//! 2. **Lossy JID→filename encoding.**  The old layout derived directory names
//!    from a hex-escaping scheme that was not reversible for any JID containing
//!    a digit (`user1@example.com` decoded back as `user\x14\x0example.com`),
//!    and truncated non-ASCII via `char as u8`.  Here JIDs are stored verbatim
//!    in `TEXT` columns and never round-tripped through a filename.
//!
//! 3. **No transactions across objects.**  Consuming a one-time prekey and
//!    persisting the session it established were two independent file writes.
//!    A crash between them either burned an OPK with no session to show for it,
//!    or left a session referencing an OPK that had already been reaped — the
//!    exact condition the `PeerResetPending` / `RecoveryPreKeySent` recovery
//!    machinery exists to paper over.  [`SqliteStore::commit_prekey_consumption`]
//!    makes that pair atomic.
//!
//! Durability: the connection runs in WAL mode with `synchronous = FULL`.  WAL
//! alone would leave a window where a committed transaction is lost on power
//! failure; for long-lived ratchet state that is not an acceptable trade, and
//! OMEMO write volume is far too low for the fsync cost to matter.

use anyhow::{anyhow, Result};
use log::{debug, warn};
use rusqlite::{params, Connection, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;

use crate::omemo::device_id::DeviceId;
use crate::omemo::protocol::{DeviceIdentity, RatchetState, X3DHKeyBundle};

impl rusqlite::types::ToSql for DeviceId {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(rusqlite::types::ToSqlOutput::Owned(
            rusqlite::types::Value::Integer(self.get() as i64),
        ))
    }
}

impl rusqlite::types::FromSql for DeviceId {
    fn column_result(v: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        i64::column_result(v).map(|n| DeviceId::from(n as u32))
    }
}

/// Current schema version. Bump when adding a migration step in [`migrate`].
const SCHEMA_VERSION: i64 = 1;

/// Magic prefix identifying a versioned OMEMO blob (`"OM"`).
const BLOB_MAGIC: u16 = 0x4F4D;

/// Blob payload encodings.
///
/// The header is deliberately outside the serde type: adding a field to a
/// struct must never require the *reader* to already know the new shape.
#[repr(u16)]
enum BlobFormat {
    /// `bincode` with the field layout current as of this schema version.
    Bincode = 1,
}

/// Serialise `value` with a 4-byte version header.
///
/// Layout: `magic:u16le | format:u16le | payload`.
fn encode_blob<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let payload = bincode::serialize(value)?;
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&BLOB_MAGIC.to_le_bytes());
    out.extend_from_slice(&(BlobFormat::Bincode as u16).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Deserialise a blob written by [`encode_blob`].
///
/// A blob without the magic header is rejected rather than guessed at; the
/// filesystem→SQLite import in `store_migrate` is the only thing that reads
/// headerless legacy data, and it applies the layout fallbacks explicitly.
fn decode_blob<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() < 4 {
        return Err(anyhow!("blob too short ({} bytes)", bytes.len()));
    }
    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    if magic != BLOB_MAGIC {
        return Err(anyhow!(
            "missing OMEMO blob header (magic {:#06x}); refusing to guess layout",
            magic
        ));
    }
    let format = u16::from_le_bytes([bytes[2], bytes[3]]);
    match format {
        x if x == BlobFormat::Bincode as u16 => {
            bincode::deserialize(&bytes[4..]).map_err(|e| anyhow!("Failed to deserialize: {}", e))
        }
        other => Err(anyhow!(
            "unknown OMEMO blob format version {} (this build understands {})",
            other,
            BlobFormat::Bincode as u16
        )),
    }
}

/// SQLite-backed OMEMO store.
///
/// The `Connection` is behind a `Mutex` so that the store presents `&self`
/// methods (matching the previous filesystem API, whose callers are spread
/// across the OMEMO and XMPP layers) while still permitting real transactions,
/// which require `&mut Connection`.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open (creating if absent) the OMEMO database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    /// Open an in-memory store. Used by tests.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self> {
        // WAL: concurrent readers while a writer is active. FULL: every commit
        // is fsynced. Ratchet state is not regenerable, so we pay the cost.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow!("OMEMO store mutex poisoned"))
    }

    /// Create the schema and apply any pending migrations.
    fn migrate(&self) -> Result<()> {
        let conn = self.lock()?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            -- Own long-term key bundles, keyed by our device id.
            CREATE TABLE IF NOT EXISTS key_bundles (
                device_id  INTEGER PRIMARY KEY,
                bundle     BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );

            -- Peer device lists (XEP-0384 devicelist node), JID stored verbatim.
            CREATE TABLE IF NOT EXISTS device_lists (
                jid         TEXT NOT NULL,
                device_id   INTEGER NOT NULL,
                PRIMARY KEY (jid, device_id)
            );
            CREATE TABLE IF NOT EXISTS device_list_meta (
                jid         TEXT PRIMARY KEY,
                last_update INTEGER NOT NULL
            );

            -- Peer identities and their pinned trust level.
            CREATE TABLE IF NOT EXISTS device_identities (
                jid         TEXT NOT NULL,
                device_id   INTEGER NOT NULL,
                identity    BLOB NOT NULL,
                trust_level TEXT NOT NULL DEFAULT 'undecided',
                PRIMARY KEY (jid, device_id)
            );

            -- Double-ratchet session state.
            CREATE TABLE IF NOT EXISTS sessions (
                jid          TEXT NOT NULL,
                device_id    INTEGER NOT NULL,
                state        BLOB NOT NULL,
                last_updated INTEGER NOT NULL,
                PRIMARY KEY (jid, device_id)
            );

            -- Per-peer-device runtime flags. Replaces the marker-file soup:
            -- failure_count, last_undecryptable, ignore_until, rebuild_needed,
            -- prekey_pending_since were each a separate file on disk.
            CREATE TABLE IF NOT EXISTS device_meta (
                jid                  TEXT NOT NULL,
                device_id            INTEGER NOT NULL,
                failure_count        INTEGER NOT NULL DEFAULT 0,
                last_undecryptable   INTEGER,
                ignore_until         INTEGER,
                rebuild_needed       INTEGER NOT NULL DEFAULT 0,
                prekey_pending_since INTEGER,
                PRIMARY KEY (jid, device_id)
            );

            CREATE TABLE IF NOT EXISTS pending_verifications (
                jid         TEXT NOT NULL,
                device_id   INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                PRIMARY KEY (jid, device_id)
            );

            CREATE TABLE IF NOT EXISTS published_device_lists (
                jid TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS published_bundles (
                device_id INTEGER PRIMARY KEY
            );

            -- Message IDs whose decryption failed, with a TTL applied on read.
            -- Stored verbatim: the old filesystem version used the sanitised
            -- filename as the returned ID, so any ID containing a character
            -- outside [A-Za-z0-9_-] came back mangled and never matched.
            CREATE TABLE IF NOT EXISTS failed_message_ids (
                msg_id    TEXT PRIMARY KEY,
                failed_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_device_meta_rebuild
                ON device_meta (rebuild_needed) WHERE rebuild_needed = 1;
            CREATE INDEX IF NOT EXISTS idx_device_meta_prekey
                ON device_meta (prekey_pending_since)
                WHERE prekey_pending_since IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_failed_at
                ON failed_message_ids (failed_at);
            ",
        )?;

        let current: i64 = conn
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);

        if current > SCHEMA_VERSION {
            return Err(anyhow!(
                "OMEMO database schema version {} is newer than this build supports ({}). \
                 Refusing to open — a downgrade would corrupt session state.",
                current,
                SCHEMA_VERSION
            ));
        }

        // Future migration steps go here, guarded on `current < N`.

        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![SCHEMA_VERSION.to_string()],
        )?;

        Ok(())
    }

    // ---------------------------------------------------------------- meta --

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let conn = self.lock()?;
        Ok(conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------- bundles --

    pub fn store_key_bundle(&self, bundle: &X3DHKeyBundle) -> Result<()> {
        let blob = encode_blob(bundle)?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO key_bundles (device_id, bundle, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(device_id) DO UPDATE SET bundle = excluded.bundle",
            params![bundle.device_id, blob, now_secs()],
        )?;
        Ok(())
    }

    pub fn load_key_bundle(&self, device_id: DeviceId) -> Result<Option<X3DHKeyBundle>> {
        let conn = self.lock()?;
        let blob: Option<Vec<u8>> = conn
            .query_row(
                "SELECT bundle FROM key_bundles WHERE device_id = ?1",
                params![device_id],
                |r| r.get(0),
            )
            .optional()?;
        match blob {
            Some(b) => Ok(Some(decode_blob(&b)?)),
            None => Ok(None),
        }
    }

    // ------------------------------------------------------------ sessions --

    pub fn save_session(&self, jid: &str, device_id: DeviceId, state: &RatchetState) -> Result<()> {
        let blob = encode_blob(state)?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO sessions (jid, device_id, state, last_updated) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(jid, device_id) DO UPDATE SET
                 state = excluded.state,
                 last_updated = excluded.last_updated",
            params![jid, device_id, blob, now_secs()],
        )?;
        Ok(())
    }

    pub fn load_session(&self, jid: &str, device_id: DeviceId) -> Result<Option<RatchetState>> {
        let conn = self.lock()?;
        let blob: Option<Vec<u8>> = conn
            .query_row(
                "SELECT state FROM sessions WHERE jid = ?1 AND device_id = ?2",
                params![jid, device_id],
                |r| r.get(0),
            )
            .optional()?;
        match blob {
            Some(b) => Ok(Some(decode_blob(&b)?)),
            None => Ok(None),
        }
    }

    /// Load every session. A blob that fails to decode is logged and removed —
    /// unlike the filesystem version it is not silently left in place to fail
    /// again on every subsequent start.
    pub fn load_all_sessions(&self) -> Result<Vec<(String, DeviceId, RatchetState)>> {
        let conn = self.lock()?;
        let mut out = Vec::new();
        let mut bad = Vec::new();
        {
            let mut stmt = conn.prepare("SELECT jid, device_id, state FROM sessions")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, DeviceId>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })?;

            for row in rows {
                let (jid, device_id, blob) = row?;
                match decode_blob::<RatchetState>(&blob) {
                    Ok(state) => out.push((jid, device_id, state)),
                    Err(e) => {
                        warn!(
                            "Failed to deserialize session for {}:{}: {} — dropping",
                            jid, device_id, e
                        );
                        bad.push((jid, device_id));
                    }
                }
            }
        }

        for (jid, device_id) in bad {
            let _ = conn.execute(
                "DELETE FROM sessions WHERE jid = ?1 AND device_id = ?2",
                params![jid, device_id],
            );
        }

        Ok(out)
    }

    pub fn delete_session(&self, jid: &str, device_id: DeviceId) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM sessions WHERE jid = ?1 AND device_id = ?2",
            params![jid, device_id],
        )?;
        Ok(())
    }

    /// Atomically persist a session and the key bundle it consumed a one-time
    /// prekey from.
    ///
    /// This is the operation the filesystem layout could not express. On the
    /// receiving side of X3DH we must, as a single indivisible step:
    ///   * record the freshly-established ratchet state, and
    ///   * write back the bundle with the consumed OPK removed (and any
    ///     replenished OPKs added).
    ///
    /// Doing these as two writes admits two failure modes on an ill-timed
    /// crash: an OPK burned with no session (peer's next message re-runs X3DH
    /// against a key we no longer hold → `PeerResetPending`), or a session
    /// whose OPK is still advertised (a replayed PreKey message re-derives a
    /// *different* session and every subsequent decrypt fails its MAC →
    /// `RecoveryPreKeySent`). Both resolve to a visible "session broken"
    /// prompt for the user.
    pub fn commit_prekey_consumption(
        &self,
        jid: &str,
        device_id: DeviceId,
        state: &RatchetState,
        bundle: &X3DHKeyBundle,
    ) -> Result<()> {
        let state_blob = encode_blob(state)?;
        let bundle_blob = encode_blob(bundle)?;
        let ts = now_secs();

        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO sessions (jid, device_id, state, last_updated) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(jid, device_id) DO UPDATE SET
                 state = excluded.state,
                 last_updated = excluded.last_updated",
            params![jid, device_id, state_blob, ts],
        )?;
        tx.execute(
            "INSERT INTO key_bundles (device_id, bundle, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(device_id) DO UPDATE SET bundle = excluded.bundle",
            params![bundle.device_id, bundle_blob, ts],
        )?;
        tx.commit()?;

        debug!(
            "Atomically committed session {}:{} + bundle {} after OPK consumption",
            jid, device_id, bundle.device_id
        );
        Ok(())
    }

    // ---------------------------------------------------------- identities --

    pub fn save_identity(&self, jid: &str, identity: &DeviceIdentity, trust: crate::omemo::storage::TrustLevel) -> Result<()> {
        let blob = encode_blob(identity)?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO device_identities (jid, device_id, identity, trust_level)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(jid, device_id) DO UPDATE SET identity = excluded.identity",
            params![jid, identity.id, blob, trust.as_str()],
        )?;
        Ok(())
    }

    pub fn load_identity(&self, jid: &str, device_id: DeviceId) -> Result<Option<DeviceIdentity>> {
        let conn = self.lock()?;
        let blob: Option<Vec<u8>> = conn
            .query_row(
                "SELECT identity FROM device_identities WHERE jid = ?1 AND device_id = ?2",
                params![jid, device_id],
                |r| r.get(0),
            )
            .optional()?;
        match blob {
            // A zero-length blob is a trust-only placeholder row written by
            // `set_trust` before the identity was ever fetched.
            Some(b) if b.is_empty() => Ok(None),
            Some(b) => Ok(Some(decode_blob(&b)?)),
            None => Ok(None),
        }
    }

    pub fn all_identities(&self) -> Result<Vec<(String, DeviceId, DeviceIdentity)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT jid, device_id, identity FROM device_identities")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, DeviceId>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (jid, device_id, blob) = row?;
            if blob.is_empty() {
                continue; // trust-only placeholder
            }
            match decode_blob::<DeviceIdentity>(&blob) {
                Ok(id) => out.push((jid, device_id, id)),
                Err(e) => warn!("Failed to load identity for {}:{}: {}", jid, device_id, e),
            }
        }
        Ok(out)
    }

    pub fn get_trust(&self, jid: &str, device_id: DeviceId) -> Result<Option<String>> {
        let conn = self.lock()?;
        Ok(conn
            .query_row(
                "SELECT trust_level FROM device_identities WHERE jid = ?1 AND device_id = ?2",
                params![jid, device_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Set the trust level, creating a placeholder row if the identity has not
    /// been fetched yet (the filesystem version happily wrote a `trust_level`
    /// file next to a non-existent `identity.bin`, so callers rely on this).
    pub fn set_trust(&self, jid: &str, device_id: DeviceId, trust: crate::omemo::storage::TrustLevel) -> Result<()> {
        let conn = self.lock()?;
        let updated = conn.execute(
            "UPDATE device_identities SET trust_level = ?3 WHERE jid = ?1 AND device_id = ?2",
            params![jid, device_id, trust.as_str()],
        )?;
        if updated == 0 {
            conn.execute(
                "INSERT INTO device_identities (jid, device_id, identity, trust_level)
                 VALUES (?1, ?2, X'', ?3)",
                params![jid, device_id, trust.as_str()],
            )?;
        }
        Ok(())
    }

    pub fn has_trust_level(&self, jid: &str, trust: crate::omemo::storage::TrustLevel) -> Result<bool> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM device_identities WHERE jid = ?1 AND trust_level = ?2",
            params![jid, trust.as_str()],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    // -------------------------------------------------------- device lists --

    pub fn save_device_list(
        &self,
        jid: &str,
        device_ids: &[DeviceId],
        last_update: i64,
    ) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM device_lists WHERE jid = ?1", params![jid])?;
        {
            let mut stmt =
                tx.prepare("INSERT INTO device_lists (jid, device_id) VALUES (?1, ?2)")?;
            for id in device_ids {
                stmt.execute(params![jid, id])?;
            }
        }
        tx.execute(
            "INSERT INTO device_list_meta (jid, last_update) VALUES (?1, ?2)
             ON CONFLICT(jid) DO UPDATE SET last_update = excluded.last_update",
            params![jid, last_update],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Returns `None` when no device list has ever been stored for `jid`,
    /// letting the caller distinguish "unknown contact" from "known, empty".
    pub fn load_device_list(&self, jid: &str) -> Result<Option<(Vec<DeviceId>, i64)>> {
        let conn = self.lock()?;
        let last_update: Option<i64> = conn
            .query_row(
                "SELECT last_update FROM device_list_meta WHERE jid = ?1",
                params![jid],
                |r| r.get(0),
            )
            .optional()?;
        let Some(last_update) = last_update else {
            return Ok(None);
        };
        let mut stmt =
            conn.prepare("SELECT device_id FROM device_lists WHERE jid = ?1 ORDER BY device_id")?;
        let ids = stmt
            .query_map(params![jid], |r| r.get::<_, DeviceId>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Some((ids, last_update)))
    }

    // -------------------------------------------------------- device meta ---

    fn upsert_device_meta(
        &self,
        jid: &str,
        device_id: DeviceId,
        column: &str,
        value: &dyn rusqlite::ToSql,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR IGNORE INTO device_meta (jid, device_id) VALUES (?1, ?2)",
            params![jid, device_id],
        )?;
        // `column` is never user-controlled: every caller passes a literal.
        let sql = format!(
            "UPDATE device_meta SET {} = ?3 WHERE jid = ?1 AND device_id = ?2",
            column
        );
        conn.execute(&sql, params![jid, device_id, value])?;
        Ok(())
    }

    fn get_device_meta_i64(
        &self,
        jid: &str,
        device_id: DeviceId,
        column: &str,
    ) -> Result<Option<i64>> {
        let conn = self.lock()?;
        let sql = format!(
            "SELECT {} FROM device_meta WHERE jid = ?1 AND device_id = ?2",
            column
        );
        Ok(conn
            .query_row(&sql, params![jid, device_id], |r| r.get::<_, Option<i64>>(0))
            .optional()?
            .flatten())
    }

    /// Record an undecryptable message and bump the failure counter in one
    /// statement — previously two separate file writes, so a crash between them
    /// lost the increment.
    pub fn record_undecryptable(
        &self,
        jid: &str,
        device_id: DeviceId,
        timestamp: i64,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO device_meta (jid, device_id, failure_count, last_undecryptable)
             VALUES (?1, ?2, 1, ?3)
             ON CONFLICT(jid, device_id) DO UPDATE SET
                 failure_count = device_meta.failure_count + 1,
                 last_undecryptable = excluded.last_undecryptable",
            params![jid, device_id, timestamp],
        )?;
        Ok(())
    }

    pub fn get_failure_count(&self, jid: &str, device_id: DeviceId) -> Result<u32> {
        Ok(self
            .get_device_meta_i64(jid, device_id, "failure_count")?
            .unwrap_or(0)
            .max(0) as u32)
    }

    pub fn reset_failure_count(&self, jid: &str, device_id: DeviceId) -> Result<()> {
        self.upsert_device_meta(jid, device_id, "failure_count", &0i64)
    }

    pub fn set_ignore_until(&self, jid: &str, device_id: DeviceId, ts: i64) -> Result<()> {
        self.upsert_device_meta(jid, device_id, "ignore_until", &ts)
    }

    pub fn get_ignore_until(&self, jid: &str, device_id: DeviceId) -> Result<Option<i64>> {
        self.get_device_meta_i64(jid, device_id, "ignore_until")
    }

    pub fn clear_ignore_until(&self, jid: &str, device_id: DeviceId) -> Result<()> {
        self.upsert_device_meta(jid, device_id, "ignore_until", &rusqlite::types::Null)
    }

    pub fn set_rebuild_needed(&self, jid: &str, device_id: DeviceId, needed: bool) -> Result<()> {
        self.upsert_device_meta(jid, device_id, "rebuild_needed", &(needed as i64))
    }

    pub fn set_prekey_pending(
        &self,
        jid: &str,
        device_id: DeviceId,
        since: Option<i64>,
    ) -> Result<()> {
        match since {
            Some(ts) => self.upsert_device_meta(jid, device_id, "prekey_pending_since", &ts),
            None => self.upsert_device_meta(
                jid,
                device_id,
                "prekey_pending_since",
                &rusqlite::types::Null,
            ),
        }
    }

    pub fn get_prekey_pending_since(&self, jid: &str, device_id: DeviceId) -> Result<Option<i64>> {
        self.get_device_meta_i64(jid, device_id, "prekey_pending_since")
    }

    pub fn all_rebuild_pending(&self) -> Result<Vec<(String, DeviceId)>> {
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare("SELECT jid, device_id FROM device_meta WHERE rebuild_needed = 1")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn all_prekey_pending(&self) -> Result<Vec<(String, DeviceId)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT jid, device_id FROM device_meta WHERE prekey_pending_since IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    // --------------------------------------------- pending verifications ----

    pub fn set_pending_verification(
        &self,
        jid: &str,
        device_id: DeviceId,
        fingerprint: &str,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO pending_verifications (jid, device_id, fingerprint) VALUES (?1, ?2, ?3)
             ON CONFLICT(jid, device_id) DO UPDATE SET fingerprint = excluded.fingerprint",
            params![jid, device_id, fingerprint],
        )?;
        Ok(())
    }

    pub fn get_pending_verification(&self, jid: &str) -> Result<Option<(DeviceId, String)>> {
        let conn = self.lock()?;
        Ok(conn
            .query_row(
                "SELECT device_id, fingerprint FROM pending_verifications
                 WHERE jid = ?1 ORDER BY device_id LIMIT 1",
                params![jid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    pub fn remove_pending_verification(&self, jid: &str, device_id: DeviceId) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM pending_verifications WHERE jid = ?1 AND device_id = ?2",
            params![jid, device_id],
        )?;
        Ok(())
    }

    // --------------------------------------------------- published markers --

    pub fn mark_device_list_published(&self, jid: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR IGNORE INTO published_device_lists (jid) VALUES (?1)",
            params![jid],
        )?;
        Ok(())
    }

    pub fn is_device_list_published(&self, jid: &str) -> Result<bool> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM published_device_lists WHERE jid = ?1",
            params![jid],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    pub fn mark_bundle_published(&self, device_id: DeviceId) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR IGNORE INTO published_bundles (device_id) VALUES (?1)",
            params![device_id],
        )?;
        Ok(())
    }

    pub fn is_bundle_published(&self, device_id: DeviceId) -> Result<bool> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM published_bundles WHERE device_id = ?1",
            params![device_id],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    // ------------------------------------------------- failed message ids ---

    pub fn persist_failed_message_id(&self, msg_id: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO failed_message_ids (msg_id, failed_at) VALUES (?1, ?2)
             ON CONFLICT(msg_id) DO UPDATE SET failed_at = excluded.failed_at",
            params![msg_id, now_secs()],
        )?;
        Ok(())
    }

    /// Return message IDs recorded within `ttl_secs`, pruning older rows.
    pub fn recent_failed_message_ids(&self, ttl_secs: u64) -> Result<Vec<String>> {
        let cutoff = now_secs().saturating_sub(ttl_secs as i64);
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM failed_message_ids WHERE failed_at < ?1",
            params![cutoff],
        )?;
        let mut stmt = conn.prepare("SELECT msg_id FROM failed_message_ids")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::omemo::keys::Secret;
    use crate::omemo::protocol::KeyPair;

    fn kp() -> KeyPair {
        KeyPair {
            public_key: crate::omemo::keys::PublicKey::new([1u8; 32]),
            private_key: Secret::new([2u8; 32]),
        }
    }

    fn state(jid: &str, device_id: DeviceId) -> RatchetState {
        RatchetState {
            initialized: true,
            is_initiator: false,
            remote_identity_key: vec![3u8; 32],
            local_identity_key_pair: kp(),
            root_key: crate::omemo::keys::RootKey::from_slice(&[4u8; 32]).unwrap(),
            send_chain_key: crate::omemo::keys::ChainKey::from_slice(&[5u8; 32]).unwrap(),
            receive_chain_key: crate::omemo::keys::ChainKey::from_slice(&[6u8; 32]).unwrap(),
            ratchet_key_pair: kp(),
            remote_ratchet_key: vec![7u8; 32],
            prev_remote_ratchet_key: vec![8u8; 32],
            send_message_number: 3,
            receive_message_number: 4,
            prev_receive_message_number: 2,
            prev_send_message_number: 1,
            skipped_message_keys: Default::default(),
            local_device_id: DeviceId::from(1),
            remote_device_id: device_id,
            remote_jid: jid.to_string(),
            establishing_base_key: Some(vec![9u8; 32]),
        }
    }

    fn bundle(device_id: DeviceId) -> X3DHKeyBundle {
        let mut opks = std::collections::HashMap::new();
        opks.insert(1u32, kp());
        opks.insert(2u32, kp());
        X3DHKeyBundle {
            device_id,
            identity_key_pair: kp(),
            signed_pre_key_id: 1,
            signed_pre_key_pair: kp(),
            signed_pre_key_signature: vec![0u8; 64],
            one_time_pre_key_pairs: opks,
            signed_pre_key_history: Default::default(),
        }
    }

    /// JIDs containing digits round-tripped incorrectly under the old
    /// hex-escaping filename scheme. Stored as TEXT there is nothing to decode.
    #[test]
    fn jids_with_digits_and_non_ascii_round_trip() {
        let s = SqliteStore::open_in_memory().unwrap();
        for jid in [
            "user1@example.com",
            "alice2@jabber.org",
            "b0b@example.com",
            "user@10.0.0.5",
            "josé@example.com",
            "中@example.com",
        ] {
            s.save_session(jid, DeviceId::from(42), &state(jid, DeviceId::from(42))).unwrap();
        }
        let all = s.load_all_sessions().unwrap();
        assert_eq!(all.len(), 6);
        for (jid, _, st) in all {
            assert_eq!(jid, st.remote_jid, "JID must survive persistence verbatim");
        }
    }

    /// Distinct JIDs that the old `char as u8` truncation collapsed onto the
    /// same directory must remain distinct rows.
    #[test]
    fn non_ascii_jids_do_not_collide() {
        let s = SqliteStore::open_in_memory().unwrap();
        s.save_session("中@a.com", DeviceId::from(1), &state("中@a.com", DeviceId::from(1))).unwrap();
        s.save_session("ح@a.com", DeviceId::from(1), &state("ح@a.com", DeviceId::from(1))).unwrap();
        assert_eq!(s.load_all_sessions().unwrap().len(), 2);
    }

    #[test]
    fn blob_header_is_versioned_and_rejects_bare_bincode() {
        let st = state("a@b.com", DeviceId::from(7));
        let blob = encode_blob(&st).unwrap();
        assert_eq!(u16::from_le_bytes([blob[0], blob[1]]), BLOB_MAGIC);
        let back: RatchetState = decode_blob(&blob).unwrap();
        assert_eq!(back.remote_jid, "a@b.com");

        // A headerless (pre-migration) blob must be refused, not misparsed.
        let bare = bincode::serialize(&st).unwrap();
        assert!(decode_blob::<RatchetState>(&bare).is_err());
    }

    #[test]
    fn prekey_consumption_is_atomic() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut b = bundle(DeviceId::from(1));
        s.store_key_bundle(&b).unwrap();

        b.one_time_pre_key_pairs.remove(&1);
        s.commit_prekey_consumption("peer@x.com", DeviceId::from(9), &state("peer@x.com", DeviceId::from(9)), &b)
            .unwrap();

        let loaded_bundle = s.load_key_bundle(DeviceId::from(1)).unwrap().unwrap();
        assert!(!loaded_bundle.one_time_pre_key_pairs.contains_key(&1));
        assert!(s.load_session("peer@x.com", DeviceId::from(9)).unwrap().is_some());
    }

    #[test]
    fn device_meta_flags_persist_independently() {
        let s = SqliteStore::open_in_memory().unwrap();
        s.set_rebuild_needed("a@b.com", DeviceId::from(1), true).unwrap();
        s.set_prekey_pending("a@b.com", DeviceId::from(2), Some(1234)).unwrap();
        s.record_undecryptable("a@b.com", DeviceId::from(1), 999).unwrap();
        s.record_undecryptable("a@b.com", DeviceId::from(1), 1000).unwrap();

        assert_eq!(s.get_failure_count("a@b.com", DeviceId::from(1)).unwrap(), 2);
        assert_eq!(s.all_rebuild_pending().unwrap(), vec![("a@b.com".into(), DeviceId::from(1))]);
        assert_eq!(s.all_prekey_pending().unwrap(), vec![("a@b.com".into(), DeviceId::from(2))]);

        s.set_rebuild_needed("a@b.com", DeviceId::from(1), false).unwrap();
        assert!(s.all_rebuild_pending().unwrap().is_empty());
    }

    /// The filesystem version returned the *sanitised filename* as the message
    /// ID, so any ID with a `@`, `.` or `/` came back mangled and never matched.
    #[test]
    fn failed_message_ids_survive_verbatim() {
        let s = SqliteStore::open_in_memory().unwrap();
        let id = "msg/1234@example.com#frag";
        s.persist_failed_message_id(id).unwrap();
        assert_eq!(s.recent_failed_message_ids(3600).unwrap(), vec![id]);
    }

    #[test]
    fn newer_schema_is_refused() {
        let s = SqliteStore::open_in_memory().unwrap();
        s.set_meta("schema_version", "9999").unwrap();
        assert!(s.migrate().is_err());
    }
}
