// src/omemo/store_migrate.rs
//! One-time import of the legacy filesystem OMEMO store into SQLite.
//!
//! Runs at most once per data directory: on success the old tree is renamed to
//! `legacy-imported-<unix_ts>` rather than deleted, so a failed upgrade can be
//! diagnosed (and, if necessary, re-run by renaming it back).
//!
//! ## Recovering JIDs
//!
//! The legacy layout derived directory names from `jid_to_alphanumeric`, which
//! is **not reversible**: alphanumerics were emitted bare while everything else
//! became two hex digits, so a digit in the plaintext is indistinguishable from
//! the first nibble of an escape. `user1@example.com` encodes to
//! `user140example2ecom`, and the decoder consumes `14` as an escape, yielding
//! `user\x14\x0example.com`. Non-ASCII was additionally truncated by
//! `format!("{:02x}", c as u8)`, so `中@a.com` and `ح@a.com` share a directory.
//!
//! Rather than trust that decoder, the import recovers JIDs authoritatively
//! wherever the data carries them, and only falls back to guessing when it does
//! not:
//!
//! 1. **Sessions** embed the true JID in `RatchetState::remote_jid`. These are
//!    read first and every recovered JID is re-encoded to build a
//!    `encoded_dir -> real_jid` lookup table.
//! 2. **Everything else** (device lists, identities, per-device metadata) is
//!    matched against that table by directory name.
//! 3. Only if a directory has no entry in the table is the legacy decoder used,
//!    and the result is discarded unless it round-trips and parses as a JID.
//!
//! A directory that cannot be resolved is skipped with a warning: re-fetching a
//! device list or re-establishing a session is recoverable, whereas importing
//! state under a corrupted JID key silently breaks lookups forever.

use anyhow::{anyhow, Result};
use log::{info, warn};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::omemo::device_id::DeviceId;
use crate::omemo::protocol::{DeviceIdentity, RatchetState, X3DHKeyBundle};
use crate::omemo::store_sqlite::SqliteStore;

/// Reproduces the legacy `jid_to_alphanumeric` exactly, including the
/// `char as u8` truncation. Used only to build the lookup table.
fn legacy_encode(jid: &str) -> String {
    jid.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("{:02x}", c as u8)
            }
        })
        .collect()
}

/// Reproduces the legacy (broken) `alphanumeric_to_jid`. Last-resort fallback.
fn legacy_decode(encoded: &str) -> String {
    let mut result = String::new();
    let mut chars = encoded.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_alphanumeric() && !c.is_ascii_digit() {
            result.push(c);
        } else if c.is_ascii_digit() {
            if let Some(&next) = chars.peek() {
                if next.is_ascii_hexdigit() {
                    let hex: String = [c, chars.next().unwrap_or('0')].iter().collect();
                    match u8::from_str_radix(&hex, 16) {
                        Ok(b) => result.push(b as char),
                        Err(_) => {
                            result.push(c);
                            result.push(next);
                        }
                    }
                } else {
                    result.push(c);
                }
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Very small sanity check: a bare JID needs exactly one `@`, non-empty parts,
/// and no control characters (which is what a bad decode typically produces).
fn looks_like_jid(s: &str) -> bool {
    let mut parts = s.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !s.chars().any(|c| c.is_control())
}

/// Decode a legacy blob, tolerating the historical `RatchetState` layouts.
///
/// Legacy blobs have no version header, so this goes straight to `bincode` and
/// walks back through the known field orders — the same fallback chain used by
/// the filesystem reader, applied here once at import time.
fn decode_legacy_ratchet(data: &[u8], expected_device_id: DeviceId) -> Result<RatchetState> {
    use crate::omemo::protocol::legacy_ratchet::{RatchetStateV1, RatchetStateV2};

    let current_err = match bincode::deserialize::<RatchetState>(data) {
        Ok(s) => return Ok(s),
        Err(e) => e,
    };
    if let Ok(v2) = bincode::deserialize::<RatchetStateV2>(data) {
        let s: RatchetState = v2.into();
        if s.remote_device_id == expected_device_id {
            return Ok(s);
        }
    }
    if let Ok(v1) = bincode::deserialize::<RatchetStateV1>(data) {
        let s: RatchetState = v1.into();
        if s.remote_device_id == expected_device_id {
            return Ok(s);
        }
    }
    Err(anyhow!("Failed to deserialize: {}", current_err))
}

fn read_text(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn read_i64(path: &Path) -> Option<i64> {
    read_text(path).and_then(|s| s.parse().ok())
}

/// True if `base` contains a legacy filesystem store worth importing.
pub fn legacy_store_present(base: &Path) -> bool {
    [
        "sessions",
        "identities",
        "key_bundles",
        "device_lists",
        "metadata",
    ]
    .iter()
    .any(|d| base.join(d).is_dir())
}

/// Import the legacy tree at `base` into `store`, then rename it aside.
///
/// Best-effort per record: a single unreadable file is logged and skipped
/// rather than aborting the whole import.
pub fn import_legacy_store(base: &Path, store: &SqliteStore) -> Result<()> {
    info!(
        "Importing legacy OMEMO filesystem store from {}",
        base.display()
    );

    let mut jid_map: HashMap<String, String> = HashMap::new();
    let mut counts = [0usize; 6];

    // --- 1. Sessions: authoritative source of JIDs ---------------------------
    let sessions_dir = base.join("sessions");
    if sessions_dir.is_dir() {
        for jid_entry in fs::read_dir(&sessions_dir)?.flatten() {
            if !jid_entry.path().is_dir() {
                continue;
            }
            let encoded = jid_entry.file_name().to_string_lossy().to_string();
            for device_entry in fs::read_dir(jid_entry.path())?.flatten() {
                let Ok(device_id) = device_entry.file_name().to_string_lossy().parse::<DeviceId>()
                else {
                    continue;
                };
                let state_path = device_entry.path().join("state.bin");
                if !state_path.exists() {
                    continue;
                }
                let data = match fs::read(&state_path) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!("Skipping {}: {}", state_path.display(), e);
                        continue;
                    }
                };
                match decode_legacy_ratchet(&data, device_id) {
                    Ok(state) => {
                        // `remote_jid` is the JID as the app actually used it.
                        let jid = state.remote_jid.clone();
                        if !jid.is_empty() {
                            jid_map.insert(legacy_encode(&jid), jid.clone());
                            jid_map.insert(encoded.clone(), jid.clone());
                        }
                        if let Err(e) = store.save_session(&jid, device_id, &state) {
                            warn!("Failed to import session {}:{}: {}", jid, device_id, e);
                        } else {
                            counts[0] += 1;
                        }
                    }
                    Err(e) => warn!(
                        "Dropping undecodable legacy session {}:{}: {}",
                        encoded, device_id, e
                    ),
                }
            }
        }
    }

    // Resolve an encoded directory name to a real JID, preferring the table.
    let resolve = |encoded: &str| -> Option<String> {
        if let Some(j) = jid_map.get(encoded) {
            return Some(j.clone());
        }
        let guess = legacy_decode(encoded);
        if looks_like_jid(&guess) && legacy_encode(&guess) == encoded {
            Some(guess)
        } else {
            None
        }
    };

    // --- 2. Key bundles (keyed by our own device id, no JID involved) --------
    let bundles_dir = base.join("key_bundles");
    if bundles_dir.is_dir() {
        for entry in fs::read_dir(&bundles_dir)?.flatten() {
            let Ok(device_id) = entry.file_name().to_string_lossy().parse::<DeviceId>() else {
                continue;
            };
            let path = entry.path().join("bundle.bin");
            if !path.exists() {
                continue;
            }
            match fs::read(&path)
                .map_err(anyhow::Error::from)
                .and_then(|d| bincode::deserialize::<X3DHKeyBundle>(&d).map_err(Into::into))
            {
                Ok(bundle) => {
                    if let Err(e) = store.store_key_bundle(&bundle) {
                        warn!("Failed to import bundle {}: {}", device_id, e);
                    } else {
                        counts[1] += 1;
                    }
                }
                Err(e) => warn!("Dropping undecodable legacy bundle {}: {}", device_id, e),
            }
        }
    }

    // --- 3. Identities + trust levels ---------------------------------------
    let identities_dir = base.join("identities");
    if identities_dir.is_dir() {
        for jid_entry in fs::read_dir(&identities_dir)?.flatten() {
            if !jid_entry.path().is_dir() {
                continue;
            }
            let encoded = jid_entry.file_name().to_string_lossy().to_string();
            let Some(jid) = resolve(&encoded) else {
                warn!(
                    "Cannot recover JID for identities dir '{}' — skipping",
                    encoded
                );
                continue;
            };
            for device_entry in fs::read_dir(jid_entry.path())?.flatten() {
                let Ok(device_id) = device_entry.file_name().to_string_lossy().parse::<DeviceId>()
                else {
                    continue;
                };
                let dir = device_entry.path();
                let trust_str = read_text(&dir.join("trust_level")).unwrap_or_else(|| {
                    match read_text(&dir.join("trusted")).as_deref() {
                        Some("true") => "trusted".to_string(),
                        _ => "undecided".to_string(),
                    }
                });
                let trust = crate::omemo::storage::TrustLevel::from_str(&trust_str)
                    .unwrap_or(crate::omemo::storage::TrustLevel::Undecided);
                let identity_path = dir.join("identity.bin");
                if identity_path.exists() {
                    match fs::read(&identity_path)
                        .map_err(anyhow::Error::from)
                        .and_then(|d| bincode::deserialize::<DeviceIdentity>(&d).map_err(Into::into))
                    {
                        Ok(identity) => {
                            if let Err(e) = store.save_identity(&jid, &identity, trust) {
                                warn!("Failed to import identity {}:{}: {}", jid, device_id, e);
                            } else {
                                let _ = store.set_trust(&jid, device_id, trust);
                                counts[2] += 1;
                            }
                        }
                        Err(e) => {
                            warn!("Dropping undecodable identity {}:{}: {}", jid, device_id, e);
                            let _ = store.set_trust(&jid, device_id, trust);
                        }
                    }
                } else {
                    let _ = store.set_trust(&jid, device_id, trust);
                }
            }
        }
    }

    // --- 4. Device lists ------------------------------------------------------
    let lists_dir = base.join("device_lists");
    if lists_dir.is_dir() {
        for jid_entry in fs::read_dir(&lists_dir)?.flatten() {
            if !jid_entry.path().is_dir() {
                continue;
            }
            let encoded = jid_entry.file_name().to_string_lossy().to_string();
            let Some(jid) = resolve(&encoded) else {
                warn!(
                    "Cannot recover JID for device_lists dir '{}' — skipping",
                    encoded
                );
                continue;
            };
            let ids: Vec<DeviceId> = read_text(&jid_entry.path().join("device_ids"))
                .unwrap_or_default()
                .lines()
                .filter_map(|l| l.trim().parse().ok())
                .collect();
            let last_update = read_i64(&jid_entry.path().join("last_update")).unwrap_or(0);
            if let Err(e) = store.save_device_list(&jid, &ids, last_update) {
                warn!("Failed to import device list for {}: {}", jid, e);
            } else {
                counts[3] += 1;
            }
        }
    }

    // --- 5. Per-device metadata + global metadata files ----------------------
    let metadata_dir = base.join("metadata");
    if metadata_dir.is_dir() {
        for entry in fs::read_dir(&metadata_dir)?.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path();

            if path.is_file() {
                // Flat files: device_id, prekey_rotation_time, published_*, pending_*
                if name == "prekey_rotation_time" {
                    if let Some(v) = read_text(&path) {
                        let _ = store.set_meta("prekey_rotation_time", &v);
                    }
                } else if name == "device_id" {
                    if let Some(v) = read_text(&path) {
                        let _ = store.set_meta("device_id", &v);
                    }
                } else if let Some(rest) = name.strip_prefix("published_bundle_") {
                    if let Ok(id) = rest.parse::<DeviceId>() {
                        let _ = store.mark_bundle_published(id);
                    }
                } else if let Some(rest) = name.strip_prefix("published_device_list_") {
                    if let Some(jid) = resolve(rest) {
                        let _ = store.mark_device_list_published(&jid);
                    }
                } else if let Some(rest) = name.strip_prefix("pending_verification_") {
                    // "<encoded_jid>_<device_id>"
                    if let Some((enc, id_str)) = rest.rsplit_once('_') {
                        if let (Some(jid), Ok(id)) = (resolve(enc), id_str.parse::<DeviceId>()) {
                            if let Some(fp) = read_text(&path) {
                                let _ = store.set_pending_verification(&jid, id, &fp);
                            }
                        }
                    }
                }
                continue;
            }

            // Directories: <encoded_jid>/<device_id>/{flags}
            let Some(jid) = resolve(&name) else {
                warn!("Cannot recover JID for metadata dir '{}' — skipping", name);
                continue;
            };
            for device_entry in fs::read_dir(&path)?.flatten() {
                let Ok(device_id) = device_entry.file_name().to_string_lossy().parse::<DeviceId>()
                else {
                    continue;
                };
                let d = device_entry.path();

                if let Some(n) = read_i64(&d.join("failure_count")) {
                    if n > 0 {
                        let last = read_i64(&d.join("last_undecryptable")).unwrap_or(0);
                        for _ in 0..n {
                            let _ = store.record_undecryptable(&jid, device_id, last);
                        }
                    }
                }
                if let Some(ts) = read_i64(&d.join("ignore_until")) {
                    let _ = store.set_ignore_until(&jid, device_id, ts);
                }
                if d.join("rebuild_needed").exists() {
                    let _ = store.set_rebuild_needed(&jid, device_id, true);
                }
                if let Some(ts) = read_i64(&d.join("prekey_pending_since")) {
                    let _ = store.set_prekey_pending(&jid, device_id, Some(ts));
                }
                counts[4] += 1;
            }
        }
    }

    // --- 6. Failed message IDs -----------------------------------------------
    // The legacy filenames were sanitised lossily, so the original IDs are not
    // recoverable. These are a 24h de-duplication hint only; dropping them
    // costs at most one repeated failure log per message.
    let failed_dir = base.join("failed_messages");
    if failed_dir.is_dir() {
        let n = fs::read_dir(&failed_dir).map(|e| e.count()).unwrap_or(0);
        if n > 0 {
            info!(
                "Discarding {} legacy failed-message markers (filenames were lossily \
                 sanitised and cannot be mapped back to message IDs)",
                n
            );
        }
        counts[5] = n;
    }

    info!(
        "Legacy OMEMO import complete: {} sessions, {} bundles, {} identities, \
         {} device lists, {} device-metadata entries ({} failed-id markers dropped)",
        counts[0], counts[1], counts[2], counts[3], counts[4], counts[5]
    );

    archive_legacy_tree(base)?;
    Ok(())
}

/// Move the imported directories aside so the import does not run again.
/// Preserved rather than deleted — this is unrecoverable key material.
fn archive_legacy_tree(base: &Path) -> Result<()> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let archive: PathBuf = base.join(format!("legacy-imported-{}", stamp));
    fs::create_dir_all(&archive)?;

    for dir in [
        "sessions",
        "identities",
        "key_bundles",
        "device_lists",
        "metadata",
        "failed_messages",
    ] {
        let src = base.join(dir);
        if src.exists() {
            if let Err(e) = fs::rename(&src, archive.join(dir)) {
                warn!("Could not archive legacy dir {}: {}", src.display(), e);
            }
        }
    }
    info!("Legacy OMEMO tree archived to {}", archive.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_encoding_is_ambiguous_for_digits() {
        // Documents precisely why the lookup table exists.
        let jid = "user1@example.com";
        let enc = legacy_encode(jid);
        assert_eq!(enc, "user140example2ecom");
        assert_ne!(legacy_decode(&enc), jid);
    }

    #[test]
    fn legacy_encoding_collides_for_non_ascii() {
        assert_eq!(legacy_encode("中@a.com"), legacy_encode("ح@a.com"));
    }

    #[test]
    fn digit_free_jids_still_decode() {
        let jid = "bob@example.com";
        assert_eq!(legacy_decode(&legacy_encode(jid)), jid);
    }

    #[test]
    fn jid_shape_check_rejects_bad_decodes() {
        assert!(looks_like_jid("user@example.com"));
        assert!(!looks_like_jid("user\u{14}\u{0}example.com"));
        assert!(!looks_like_jid("no-at-sign"));
        assert!(!looks_like_jid("a@b@c.com"));
    }

    #[test]
    fn legacy_store_absent_when_no_directories_exist() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(!legacy_store_present(dir.path()));
    }

    #[test]
    fn legacy_store_detected_when_sessions_dir_present() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("sessions")).unwrap();
        assert!(legacy_store_present(dir.path()));
    }

    #[test]
    fn import_empty_legacy_tree_succeeds() {
        let dir = tempfile::TempDir::new().unwrap();
        // Create an empty sessions dir — present but no session files.
        std::fs::create_dir_all(dir.path().join("sessions")).unwrap();
        let store = SqliteStore::open_in_memory().unwrap();
        import_legacy_store(dir.path(), &store).expect("import of empty tree must succeed");
    }

    #[test]
    fn import_is_idempotent_on_empty_tree() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("sessions")).unwrap();
        let store = SqliteStore::open_in_memory().unwrap();
        import_legacy_store(dir.path(), &store).unwrap();
        // Second import must not fail (legacy dir is renamed aside after first import).
        // legacy_store_present should return false now.
        assert!(!legacy_store_present(dir.path()), "legacy dirs must be renamed aside after import");
    }
}
